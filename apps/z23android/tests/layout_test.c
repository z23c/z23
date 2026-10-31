/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "layout.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEAD "{\"schema\":\"zcl.layout_recipe.v1\",\"id\":\"t\","
static char reason[160];

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
    char *json = calloc(1, 4096);
    assert(json);
    strcat(json, HEAD "\"screens\":{\"home\":");
    for (int i = 1; i < levels; ++i) strcat(json, "{\"type\":\"column\",\"children\":[");
    strcat(json, "{\"type\":\"text\"}");
    for (int i = 1; i < levels; ++i) strcat(json, "]}");
    strcat(json, "}}");
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
    strcat(json, name);
    strcat(json, "\":{\"type\":\"column\",\"children\":[");
    for (int i = 0; i < leaves; ++i) strcat(json, i ? ",{\"type\":\"text\"}" : "{\"type\":\"text\"}");
    strcat(json, "]}");
}
static void node_limit(void)
{
    char *json = calloc(1, 8192);
    assert(json);
    strcpy(json, HEAD "\"screens\":{\"");
    screen(json, "a", 255);
    strcat(json, "}}");
    struct zapp_layout *layout = parse(json);
    assert(layout && layout->node_count == ZAPP_LAYOUT_MAX_NODES);
    zapp_layout_free(layout);
    strcpy(json, HEAD "\"screens\":{\"");
    screen(json, "a", 256);
    strcat(json, "}}");
    refused(json, "more than 256 nodes");
    strcpy(json, HEAD "\"screens\":{\"");
    screen(json, "a", 255);
    strcat(json, ",\"");
    screen(json, "b", 0);
    strcat(json, "}}");
    refused(json, "more than 256 nodes");
    free(json);
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
static void card_fields(void)
{
    struct json_value card;
    char out[16];
    static const char text[] = "{\"schema\":\"zcl.clip_card.v1\",\"caption\":\"caf\\u00e9 \\u00e9\\u00e9\\u00e9\","
        "\"counts\":{\"comments\":3,\"ratio\":0.5,\"live\":true},\"author\":{\"name\":\"Dana\"},\"tags\":[\"a\"],\"gone\":null}";
    json_init(&card);
    assert(json_read(&card, text, strlen(text)));
    assert(zapp_card_field(&card, "counts.comments", out, sizeof(out)) && !strcmp(out, "3"));
    assert(zapp_card_field(&card, "counts.ratio", out, sizeof(out)) && !strcmp(out, "0.5"));
    assert(zapp_card_field(&card, "counts.live", out, sizeof(out)) && !strcmp(out, "true"));
    assert(zapp_card_field(&card, "author.name", out, sizeof(out)) && !strcmp(out, "Dana"));
    assert(!zapp_card_field(&card, "counts.missing", out, sizeof(out)) && !out[0]);
    assert(!zapp_card_field(&card, "author.name.deeper", out, sizeof(out)) && !out[0]);
    assert(!zapp_card_field(&card, "counts", out, sizeof(out)) && !out[0]);
    assert(!zapp_card_field(&card, "tags", out, sizeof(out)) && !out[0]);
    assert(!zapp_card_field(&card, "gone", out, sizeof(out)) && !out[0]);
    assert(!zapp_card_field(&card, "", out, sizeof(out)) && !zapp_card_field(&card, "a..b", out, sizeof(out)));
    assert(!zapp_card_field(NULL, "caption", out, sizeof(out)) && !zapp_card_field(&card, NULL, out, sizeof(out)));
    /* Each é is 2 bytes: a cut inside one drops it whole. */
    assert(zapp_card_field(&card, "caption", out, 10) && !strcmp(out, "caf\xc3\xa9 \xc3\xa9"));
    assert(zapp_card_field(&card, "caption", out, 9) && !strcmp(out, "caf\xc3\xa9 \xc3\xa9"));
    assert(zapp_card_field(&card, "caption", out, 8) && !strcmp(out, "caf\xc3\xa9 "));
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
    size_limit();
    malformed_documents();
    card_fields();
    puts("layout tests passed");
    return 0;
}
