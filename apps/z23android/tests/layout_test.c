/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "layout.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEAD "{\"schema\":\"zcl.layout_recipe.v1\",\"id\":\"t\","
static char reason[160];

#define JSON_CAP 8192
/* Appends text to json, which holds JSON_CAP bytes. */
static void put(char *json, const char *text)
{
    size_t used = strlen(json), length = strlen(text);
    assert(used + length < JSON_CAP);
    memcpy(json + used, text, length + 1);
}
/* Starts json over with text. */
static void set(char *json, const char *text) { json[0] = 0; put(json, text); }

static struct zapp_layout *parse(const char *json)
{
    return zapp_layout_parse(json, strlen(json), reason, sizeof(reason));
}
/* The document must be refused, with a reason that contains want. */
static void refused(const char *json, const char *want)
{
    struct zapp_layout *layout = parse(json);
    assert(!layout);
    assert(strstr(reason, want));
}
static void valid_layout(void)
{
    struct zapp_layout *layout = parse(HEAD
        "\"theme\":{\"background\":\"#102030\",\"text\":\"#FFFFFF\",\"accent\":\"#00ff7f\"},"
        "\"screens\":{\"feed\":{\"container\":\"pager_vertical\",\"card\":\"clip\",\"children\":["
        "{\"type\":\"video\",\"field\":\"media\"},"
        "{\"type\":\"text\",\"field\":\"caption\",\"style\":\"title\",\"max_lines\":3},"
        "{\"type\":\"row\",\"children\":[{\"type\":\"action\",\"id\":\"react\"},"
        "{\"type\":\"counter\",\"field\":\"counts.comments\"},{\"type\":\"avatar\",\"field\":\"author.name\"}]},"
        "{\"type\":\"grid\",\"columns\":3,\"children\":[{\"type\":\"image\"},{\"type\":\"stack\"},{\"type\":\"list\"},{\"type\":\"column\"}]}]}}}");
    assert(layout);
    assert(!strcmp(layout->id, "t") && layout->screen_count == 1 && layout->node_count == 12);
    assert(layout->theme.background == 0xff102030u && layout->theme.text == 0xffffffffu);
    assert(layout->theme.accent == 0xff00ff7fu && layout->theme.muted == 0xff9a9a9au);
    const struct zapp_node *feed = zapp_layout_screen(layout, "feed");
    assert(feed && feed->kind == ZAPP_NODE_PAGER_VERTICAL && !strcmp(feed->card, "clip") && feed->child_count == 4);
    assert(feed->children[0].kind == ZAPP_NODE_VIDEO && !strcmp(feed->children[0].field, "media"));
    assert(feed->children[1].style == ZAPP_STYLE_TITLE && feed->children[1].max_lines == 3);
    assert(feed->children[2].kind == ZAPP_NODE_ROW && feed->children[2].child_count == 3);
    assert(!strcmp(feed->children[2].children[0].id, "react") && feed->children[2].children[1].kind == ZAPP_NODE_COUNTER);
    assert(feed->children[2].children[2].kind == ZAPP_NODE_AVATAR && feed->children[3].columns == 3);
    assert(feed->children[3].children[0].kind == ZAPP_NODE_IMAGE && feed->children[0].columns == 2);
    assert(!zapp_layout_screen(layout, "missing") && !zapp_layout_screen(NULL, "feed"));
    zapp_layout_free(layout);
}
static void unknown_fields_are_ignored(void)
{
    struct zapp_layout *layout = parse(HEAD "\"future\":{\"a\":[1,2]},\"screens\":{\"home\":{\"type\":\"column\","
        "\"sparkle\":true,\"children\":[{\"type\":\"action\",\"id\":\"scan\",\"url\":\"http://example.invalid\","
        "\"method\":\"wallet.send\",\"style\":\"neon\"}]}}}");
    assert(layout);
    const struct zapp_node *home = zapp_layout_screen(layout, "home");
    assert(home && home->child_count == 1 && !strcmp(home->children[0].id, "scan"));
    assert(home->children[0].style == ZAPP_STYLE_BODY);
    zapp_layout_free(layout);
}
static void unknown_primitive_is_refused(void)
{
    refused(HEAD "\"screens\":{\"home\":{\"type\":\"column\",\"children\":[{\"type\":\"webview\"}]}}}", "unknown primitive");
    refused(HEAD "\"screens\":{\"home\":{\"container\":\"carousel\"}}}", "unknown primitive");
    refused(HEAD "\"screens\":{\"home\":{\"children\":[]}}}", "needs a type");
}
static void bad_color_is_refused(void)
{
    static const char *const colors[] = {"\"#12345g\"", "\"red\"", "\"#fff\"", "\"#1234567\"", "\"123456\"", "12", "\"\""};
    for (size_t i = 0; i < sizeof(colors) / sizeof(colors[0]); ++i) {
        char json[400];
        snprintf(json, sizeof(json), HEAD "\"theme\":{\"accent\":%s},\"screens\":{\"home\":{\"type\":\"column\"}}}", colors[i]);
        refused(json, "accent must be #rrggbb");
    }
    refused(HEAD "\"theme\":5,\"screens\":{\"home\":{\"type\":\"column\"}}}", "theme must be an object");
}
/* A column nested to the given number of levels, the innermost holding one text leaf. */
static char *nested(int levels)
{
    char *json = calloc(1, JSON_CAP);
    assert(json);
    put(json, HEAD "\"screens\":{\"home\":");
    for (int i = 1; i < levels; ++i) put(json, "{\"type\":\"column\",\"children\":[");
    put(json, "{\"type\":\"text\"}");
    for (int i = 1; i < levels; ++i) put(json, "]}");
    put(json, "}}");
    return json;
}
static void depth_limit(void)
{
    char *ok = nested(ZAPP_LAYOUT_MAX_DEPTH), *deep = nested(ZAPP_LAYOUT_MAX_DEPTH + 1);
    struct zapp_layout *layout = parse(ok);
    assert(layout);
    zapp_layout_free(layout);
    refused(deep, "deeper than 8 levels");
    free(ok); free(deep);
}
/* A screen named name whose root column holds the given number of text leaves. */
static void screen(char *json, const char *name, int leaves)
{
    put(json, name);
    put(json, "\":{\"type\":\"column\",\"children\":[");
    for (int i = 0; i < leaves; ++i) put(json, i ? ",{\"type\":\"text\"}" : "{\"type\":\"text\"}");
    put(json, "]}");
}
static void node_limit(void)
{
    char *json = calloc(1, JSON_CAP);
    assert(json);
    set(json, HEAD "\"screens\":{\"");
    screen(json, "a", 255);
    put(json, "}}");
    struct zapp_layout *layout = parse(json);
    assert(layout && layout->node_count == ZAPP_LAYOUT_MAX_NODES);
    zapp_layout_free(layout);
    set(json, HEAD "\"screens\":{\"");
    screen(json, "a", 256);
    put(json, "}}");
    refused(json, "more than 256 nodes");
    set(json, HEAD "\"screens\":{\"");
    screen(json, "a", 255);
    put(json, ",\"");
    screen(json, "b", 0);
    put(json, "}}");
    refused(json, "more than 256 nodes");
    free(json);
}
static void screens_json(char *json, size_t screens)
{
    set(json, HEAD "\"screens\":{");
    for (size_t i = 0; i < screens; ++i)
    {
        char piece[48];
        snprintf(piece, sizeof(piece), "%s\"s%zu\":{\"type\":\"column\"}", i ? "," : "", i);
        put(json, piece);
    }
    put(json, "}}");
}
static void screen_and_name_limits(void)
{
    char json[JSON_CAP], name[ZAPP_NAME_CAP + 2];
    screens_json(json, ZAPP_LAYOUT_MAX_SCREENS);
    struct zapp_layout *layout = parse(json);
    assert(layout && layout->screen_count == ZAPP_LAYOUT_MAX_SCREENS);
    zapp_layout_free(layout);
    screens_json(json, ZAPP_LAYOUT_MAX_SCREENS + 1);
    refused(json, "more than 16 screens");
    memset(name, 'a', ZAPP_NAME_CAP - 1); name[ZAPP_NAME_CAP - 1] = 0;
    snprintf(json, sizeof(json), HEAD "\"screens\":{\"%s\":{\"type\":\"column\"}}}", name);
    layout = parse(json);
    assert(layout);
    zapp_layout_free(layout);
    memset(name, 'a', ZAPP_NAME_CAP); name[ZAPP_NAME_CAP] = 0;
    snprintf(json, sizeof(json), HEAD "\"screens\":{\"%s\":{\"type\":\"column\"}}}", name);
    refused(json, "a screen name is too long");
    snprintf(json, sizeof(json), HEAD "\"screens\":{\"home\":{\"type\":\"action\",\"id\":\"%s\"}}}", name);
    refused(json, "id must be a short name");
    memset(name, 'a', ZAPP_NAME_CAP - 1); name[ZAPP_NAME_CAP - 1] = 0;
    snprintf(json, sizeof(json), HEAD "\"screens\":{\"home\":{\"type\":\"action\",\"id\":\"%s\"}}}", name);
    layout = parse(json);
    assert(layout);
    zapp_layout_free(layout);
}
static void size_limit(void)
{
    static const char tail[] = "\"screens\":{\"home\":{\"type\":\"column\"}}}";
    size_t head = strlen(HEAD), size = ZAPP_LAYOUT_MAX_BYTES;
    char *json = malloc(size + 2);
    assert(json);
    memset(json, ' ', size + 1);
    memcpy(json, HEAD, head);
    memcpy(json + size - strlen(tail), tail, strlen(tail));
    struct zapp_layout *layout = zapp_layout_parse(json, size, reason, sizeof(reason));
    assert(layout);
    zapp_layout_free(layout);
    memcpy(json + size + 1 - strlen(tail), tail, strlen(tail));
    assert(!zapp_layout_parse(json, size + 1, reason, sizeof(reason)) && strstr(reason, "64 KiB"));
    free(json);
}
static void malformed_documents(void)
{
    refused("{", "not valid JSON");
    refused("[]", "zcl.layout_recipe.v1");
    refused("{\"schema\":\"zcl.layout_recipe.v2\",\"screens\":{\"home\":{\"type\":\"column\"}}}", "zcl.layout_recipe.v1");
    refused(HEAD "\"screens\":{}}", "at least one screen");
    refused(HEAD "\"screens\":{\"home\":{\"type\":\"column\",\"children\":{}}}}", "children must be an array");
    refused(HEAD "\"screens\":{\"home\":{\"type\":\"action\",\"id\":\"a/b\"}}}", "not allowed");
    assert(!zapp_layout_parse(NULL, 0, NULL, 0));
}
static const char card_text[] = "{\"schema\":\"zcl.clip_card.v1\",\"caption\":\"caf\\u00e9 \\u00e9\\u00e9\\u00e9\","
        "\"counts\":{\"comments\":3,\"ratio\":0.5,\"live\":true},\"author\":{\"name\":\"Dana\"},\"tags\":[\"a\"],\"gone\":null}";
static void card_paths(struct json_value *card)
{
    char out[16];
    assert(zapp_card_field(card, "counts.comments", out, sizeof(out)) && !strcmp(out, "3"));
    assert(zapp_card_field(card, "counts.ratio", out, sizeof(out)) && !strcmp(out, "0.5"));
    assert(zapp_card_field(card, "counts.live", out, sizeof(out)) && !strcmp(out, "true"));
    assert(zapp_card_field(card, "author.name", out, sizeof(out)) && !strcmp(out, "Dana"));
    assert(!zapp_card_field(card, "counts.missing", out, sizeof(out)) && !out[0]);
    assert(!zapp_card_field(card, "author.name.deeper", out, sizeof(out)) && !out[0]);
    assert(!zapp_card_field(card, "counts", out, sizeof(out)) && !out[0]);
    assert(!zapp_card_field(card, "tags", out, sizeof(out)) && !out[0]);
    assert(!zapp_card_field(card, "gone", out, sizeof(out)) && !out[0]);
    assert(!zapp_card_field(card, "", out, sizeof(out)) && !zapp_card_field(card, "a..b", out, sizeof(out)));
    assert(!zapp_card_field(NULL, "caption", out, sizeof(out)) && !zapp_card_field(card, NULL, out, sizeof(out)));
}
static void card_cuts(struct json_value *card)
{
    char out[16];
    /* Each é is 2 bytes: a cut inside one drops it whole. */
    assert(zapp_card_field(card, "caption", out, 10) && !strcmp(out, "caf\xc3\xa9 \xc3\xa9"));
    assert(zapp_card_field(card, "caption", out, 9) && !strcmp(out, "caf\xc3\xa9 \xc3\xa9"));
    assert(zapp_card_field(card, "caption", out, 8) && !strcmp(out, "caf\xc3\xa9 "));
}
static void card_fields(void)
{
    struct json_value card;
    json_init(&card);
    assert(json_read(&card, card_text, strlen(card_text)));
    card_paths(&card);
    card_cuts(&card);
    assert(zapp_card_is(&card, "clip") && !zapp_card_is(&card, "phone") && !zapp_card_is(NULL, "clip"));
    json_free(&card);
}
int main(void)
{
    valid_layout();
    unknown_fields_are_ignored();
    unknown_primitive_is_refused();
    bad_color_is_refused();
    depth_limit();
    node_limit();
    screen_and_name_limits();
    size_limit();
    malformed_documents();
    card_fields();
    puts("layout tests passed");
    return 0;
}
