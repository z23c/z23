/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Structured fleet wiki entries. See session/fleet_wiki_entry.h. */

#include "session/fleet_wiki_entry.h"

#include "session/fleet_board_proto.h"
#include "zutf8/zutf8.h"

#include <ctype.h>
#include <string.h>

static bool entry_fail(const char **why_out, const char *why)
{
    if (why_out)
        *why_out = why;
    return false;
}

/* A string value of min_len..max_len bytes with no control bytes. */
static bool entry_text_ok(const struct json_value *v, size_t min_len,
                          size_t max_len)
{
    if (!v || v->type != JSON_STR || !v->val.s)
        return false;
    size_t n = strlen(v->val.s);
    if (n < min_len || n > max_len || !zutf8_validate_n(v->val.s, n))
        return false;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)v->val.s[i] < 0x20u ||
            (unsigned char)v->val.s[i] == 0x7fu)
            return false;
    return true;
}

static bool entry_keys_in(const struct json_value *obj,
                         const char *const *allowed, size_t count)
{
    size_t present = 0;
    for (size_t k = 0; k < count; k++)
        if (json_get(obj, allowed[k]))
            present++;
    /* Every member is one of the allowed keys exactly once: an unknown key
     * or a repeated one makes the member count exceed the keys present. */
    return present == obj->num_children;
}

/* YYYY-MM-DDTHH:MM:SSZ with in-range fields. */
static bool entry_updated_ok(const struct json_value *v)
{
    static const char shape[] = "dddd-dd-ddTdd:dd:ddZ";
    if (!entry_text_ok(v, 20, 20))
        return false;
    const char *s = v->val.s;
    for (size_t i = 0; i < 20; i++) {
        bool digit = shape[i] == 'd';
        if (digit ? !isdigit((unsigned char)s[i]) : s[i] != shape[i])
            return false;
    }
    int month = (s[5] - '0') * 10 + (s[6] - '0');
    int day = (s[8] - '0') * 10 + (s[9] - '0');
    int hour = (s[11] - '0') * 10 + (s[12] - '0');
    int minute = (s[14] - '0') * 10 + (s[15] - '0');
    int second = (s[17] - '0') * 10 + (s[18] - '0');
    return month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
           hour <= 23 && minute <= 59 && second <= 59;
}

static bool entry_lesson_ok(const struct json_value *lesson)
{
    static const char *const keys[] = {"rule", "why", "evidence"};
    return lesson && lesson->type == JSON_OBJ &&
           entry_keys_in(lesson, keys, 3) &&
           entry_text_ok(json_get(lesson, "rule"), 1,
                         FLEET_WIKI_ENTRY_RULE_MAX) &&
           entry_text_ok(json_get(lesson, "why"), 0,
                         FLEET_WIKI_ENTRY_WHY_MAX) &&
           entry_text_ok(json_get(lesson, "evidence"), 0,
                         FLEET_WIKI_ENTRY_EVIDENCE_MAX);
}

static bool entry_lessons_ok(const struct json_value *lessons)
{
    if (!lessons || lessons->type != JSON_ARR)
        return false;
    size_t n = json_size(lessons);
    if (n < 1 || n > FLEET_WIKI_ENTRY_LESSONS_MAX)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!entry_lesson_ok(json_at(lessons, i)))
            return false;
    return true;
}

static bool entry_applies_ok(const struct json_value *applies)
{
    if (!applies || applies->type != JSON_ARR)
        return false;
    size_t n = json_size(applies);
    if (n > FLEET_WIKI_ENTRY_APPLIES_MAX)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!entry_text_ok(json_at(applies, i), 1,
                           FLEET_WIKI_ENTRY_APPLIES_LEN_MAX))
            return false;
    return true;
}

/* Name of the first violated rule, or NULL when the object is a valid
 * entry. */
static const char *entry_violation(const struct json_value *root)
{
    static const char *const keys[] = {"schema", "topic", "summary",
                                       "lessons", "applies_to", "updated"};
    if (!root || root->type != JSON_OBJ || !entry_keys_in(root, keys, 6))
        return "entry must be a JSON object with only the schema's keys";
    const struct json_value *schema = json_get(root, "schema");
    if (!entry_text_ok(schema, 1, 64) ||
        strcmp(schema->val.s, FLEET_WIKI_ENTRY_SCHEMA) != 0)
        return "schema must be zcl.fleet_wiki_entry.v1";
    const struct json_value *topic = json_get(root, "topic");
    if (!entry_text_ok(topic, 1, FLEET_BOARD_SLUG_MAX) ||
        !fleet_board_slug_valid(topic->val.s))
        return "topic must be 1..64 bytes of [a-z0-9-]";
    if (!entry_text_ok(json_get(root, "summary"), 1,
                       FLEET_WIKI_ENTRY_SUMMARY_MAX))
        return "summary must be 1..200 printable bytes";
    if (!entry_lessons_ok(json_get(root, "lessons")))
        return "lessons must be 1..16 objects of rule, why, evidence "
               "within their byte limits";
    if (!entry_applies_ok(json_get(root, "applies_to")))
        return "applies_to must be at most 16 strings of 1..64 bytes";
    if (!entry_updated_ok(json_get(root, "updated")))
        return "updated must be ISO-8601 UTC, YYYY-MM-DDTHH:MM:SSZ";
    return NULL;
}

enum fleet_wiki_parse_status fleet_wiki_entry_parse_checked(
    const char *text, size_t len, struct json_value *out, const char **why_out)
{
    if (why_out) *why_out = NULL;
    if (!text || !out) {
        (void)entry_fail(why_out, "no entry text or output");
        return FLEET_WIKI_PARSE_NOT_ENTRY;
    }
    json_init(out);
    if (len == 0 || text[0] != '{' || !json_valid(text, len)) {
        (void)entry_fail(why_out, "entry is not a JSON object");
        return FLEET_WIKI_PARSE_NOT_ENTRY;
    }
    /* json_valid and json_read share grammar: valid bytes that cannot be
     * materialized are allocation failure, never evidence of absent knowledge. */
    if (!json_read(out, text, len)) {
        json_free(out); json_init(out);
        (void)entry_fail(why_out, "entry allocation failed");
        return FLEET_WIKI_PARSE_ALLOC_FAILED;
    }
    const char *why = entry_violation(out);
    if (why) {
        json_free(out); json_init(out);
        (void)entry_fail(why_out, why);
        return FLEET_WIKI_PARSE_NOT_ENTRY;
    }
    return FLEET_WIKI_PARSE_ENTRY;
}

bool fleet_wiki_entry_parse(const char *text, size_t len,
                            struct json_value *out, const char **why_out)
{
    return fleet_wiki_entry_parse_checked(text, len, out, why_out) ==
        FLEET_WIKI_PARSE_ENTRY;
}

static unsigned char ascii_fold(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + ('a' - 'A')) : c;
}

/* Case-insensitive substring over ASCII letters only; every other byte
 * compares exactly. */
static bool contains_folded(const char *hay, const char *needle)
{
    size_t nl = strlen(needle);
    if (nl == 0)
        return true;
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < nl && hay[i] &&
               ascii_fold((unsigned char)hay[i]) ==
                   ascii_fold((unsigned char)needle[i]))
            i++;
        if (i == nl)
            return true;
    }
    return false;
}

static bool applies_to_matches(const struct json_value *entry, const char *needle)
{
    const struct json_value *applies = json_get(entry, "applies_to");
    for (size_t i = 0; applies && i < json_size(applies); i++)
        if (contains_folded(json_get_str(json_at(applies, i)), needle))
            return true;
    return false;
}

static bool lesson_field_matches(const struct json_value *entry,
                                 const char *key, const char *needle)
{
    const struct json_value *lessons = json_get(entry, "lessons");
    for (size_t i = 0; lessons && i < json_size(lessons); i++)
        if (contains_folded(json_get_str(json_get(json_at(lessons, i), key)),
                            needle))
            return true;
    return false;
}

size_t fleet_wiki_entry_matched_fields(const struct json_value *entry,
    const char *slug, const char *needle, const char *out[FLEET_WIKI_MATCH_FIELDS])
{
    size_t n = 0;
    if (!entry || !needle || !needle[0])
        return 0;
    if (slug && contains_folded(slug, needle))
        out[n++] = "slug";
    if (contains_folded(json_get_str(json_get(entry, "topic")), needle))
        out[n++] = "topic";
    if (contains_folded(json_get_str(json_get(entry, "summary")), needle))
        out[n++] = "summary";
    if (applies_to_matches(entry, needle))
        out[n++] = "applies_to";
    if (lesson_field_matches(entry, "rule", needle))
        out[n++] = "rule";
    if (lesson_field_matches(entry, "why", needle))
        out[n++] = "why";
    return n;
}

void fleet_wiki_plain_summary(const char *text, size_t len,
                              char out[FLEET_WIKI_SUMMARY_MAX + 1])
{
    size_t n = 0;
    while (n < len && text[n] != '\r' && text[n] != '\n')
        n++;
    if (n > FLEET_WIKI_SUMMARY_MAX) {
        n = FLEET_WIKI_SUMMARY_MAX;
        while (n > 0 && ((unsigned char)text[n] & 0xC0) == 0x80)
            n--;
    }
    memcpy(out, text, n);
    out[n] = 0;
}

size_t fleet_wiki_page_matched_fields(const char *slug, const char *title,
    const char *summary, const char *needle, const char *out[3])
{
    size_t n = 0;
    if (!needle || !needle[0])
        return 0;
    if (slug && contains_folded(slug, needle))
        out[n++] = "slug";
    if (title && contains_folded(title, needle))
        out[n++] = "title";
    if (summary && contains_folded(summary, needle))
        out[n++] = "summary";
    return n;
}

bool fleet_wiki_entry_matches(const struct json_value *entry,
                              const char *needle)
{
    if (!entry || !needle)
        return false;
    if (!needle[0])
        return true;
    const char *fields[FLEET_WIKI_MATCH_FIELDS];
    return fleet_wiki_entry_matched_fields(entry, NULL, needle, fields) > 0;
}

static bool wiki_query_applies(const struct json_value *entry, const char *exact)
{
    if (!exact || !exact[0]) return true;
    const struct json_value *applies = json_get(entry, "applies_to");
    for (size_t i = 0; i < json_size(applies); i++) {
        if (!strcmp(json_get_str(json_at(applies, i)), exact)) return true;
    }
    return false;
}

bool fleet_wiki_entry_query_matches(const struct json_value *entry,
    const struct fleet_wiki_entry_query *query)
{
    if (!entry || !query || !query->q) return false;
    if (query->topic && query->topic[0] &&
        strcmp(json_get_str(json_get(entry, "topic")), query->topic)) return false;
    return wiki_query_applies(entry, query->applies_to) &&
        (fleet_wiki_entry_matches(entry, query->q) ||
         (query->slug && query->slug[0] && contains_folded(query->slug, query->q)));
}

static const char *review_violation(const struct json_value *root)
{
    static const char *const keys[] = {
        "schema", "target", "verdict", "rating", "rationale"
    };
    if (!entry_keys_in(root, keys, 5))
        return "review contains unknown or duplicate keys";
    const struct json_value *target = json_get(root, "target");
    uint8_t id[32];
    char canonical[65];
    if (!entry_text_ok(target, 64, 64) ||
        !fleet_board_id_from_hex(target->val.s, id))
        return "review target must be an exact 64-character revision id";
    fleet_board_id_to_hex(id, canonical);
    static const uint8_t zero[32];
    if (memcmp(id, zero, 32) == 0 || strcmp(canonical, target->val.s))
        return "review target must be a nonzero canonical lowercase id";
    const struct json_value *verdict = json_get(root, "verdict");
    if (!entry_text_ok(verdict, 1, 15) ||
        (strcmp(verdict->val.s, "approve") &&
         strcmp(verdict->val.s, "request-changes") &&
         strcmp(verdict->val.s, "comment")))
        return "review verdict must be approve, request-changes or comment";
    const struct json_value *rating = json_get(root, "rating");
    if (rating && (rating->type != JSON_INT || rating->val.i < 1 || rating->val.i > 5))
        return "review rating must be an integer from 1 through 5";
    if (!entry_text_ok(json_get(root, "rationale"), 1, 1000))
        return "review rationale must be 1..1000 printable UTF-8 bytes";
    return NULL;
}


/* Materialization is separate from recognizing the reserved review schema.
 * Invalid JSON, including escaped NUL, remains an inert non-review body. */
static bool review_materialize(const char *text, size_t len,
    struct json_value *out, enum fleet_wiki_review_status *status, const char **why)
{
    size_t start = 0;
    while (text && start < len && (text[start] == ' ' || text[start] == 9 ||
        text[start] == 10 || text[start] == 13)) start++;
    if (!text || start == len || text[start] != '{' || !json_valid(text, len))
        return false;
    if (json_read(out, text, len)) return true;
    json_free(out); json_init(out);
    if (why) *why = "review allocation failed";
    *status = FLEET_WIKI_REVIEW_ALLOC_FAILED;
    return false;
}

enum fleet_wiki_review_status fleet_wiki_review_parse(
    const char *text, size_t len, struct json_value *out, const char **why)
{
    if (why) *why = NULL;
    if (!out) return FLEET_WIKI_REVIEW_INVALID;
    json_init(out);
    enum fleet_wiki_review_status status = FLEET_WIKI_NOT_REVIEW;
    if (!review_materialize(text, len, out, &status, why)) return status;
    const struct json_value *schema = json_get(out, "schema");
    if (out->type != JSON_OBJ || !schema || schema->type != JSON_STR ||
        strcmp(schema->val.s, FLEET_WIKI_REVIEW_SCHEMA)) {
        json_free(out); json_init(out);
        return FLEET_WIKI_NOT_REVIEW;
    }
    const char *violation = review_violation(out);
    if (!violation) return FLEET_WIKI_REVIEW_VALID;
    if (why) *why = violation;
    json_free(out); json_init(out);
    return FLEET_WIKI_REVIEW_INVALID;
}
