/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Structured fleet wiki entries (`zcl.fleet_wiki_entry.v1`): the JSON form a
 * wiki page body may take so an agent can find a lesson without reading prose.
 *
 *   { "schema":     "zcl.fleet_wiki_entry.v1",
 *     "topic":      slug-like, 1..64 bytes of [a-z0-9-],
 *     "summary":    1..200 bytes,
 *     "lessons":    1..16 of { "rule": 1..200, "why": 0..400,
 *                              "evidence": 0..400 } bytes each,
 *     "applies_to": 0..16 strings of 1..64 bytes,
 *     "updated":    "YYYY-MM-DDTHH:MM:SSZ" }
 *
 * Every string is well-formed UTF-8 without control bytes. Only the keys
 * above are accepted, each at most once.
 * A page whose body is not such an entry stays a plain text page. */

#ifndef ZCL_SESSION_FLEET_WIKI_ENTRY_H
#define ZCL_SESSION_FLEET_WIKI_ENTRY_H

#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>

#define FLEET_WIKI_ENTRY_SCHEMA "zcl.fleet_wiki_entry.v1"
#define FLEET_WIKI_DISCOVERY_IDENTITY_SCHEMA "zcl.fleet_wiki_revision.v1"

enum {
    FLEET_WIKI_ENTRY_SUMMARY_MAX = 200,
    FLEET_WIKI_ENTRY_RULE_MAX = 200,
    FLEET_WIKI_ENTRY_WHY_MAX = 400,
    FLEET_WIKI_ENTRY_EVIDENCE_MAX = 400,
    FLEET_WIKI_ENTRY_LESSONS_MAX = 16,
    FLEET_WIKI_ENTRY_APPLIES_MAX = 16,
    FLEET_WIKI_ENTRY_APPLIES_LEN_MAX = 64,
};

/* Parse and validate `text[0..len)`. On success returns true and `out`
 * (caller-initialised or fresh) owns the parsed object; free it with
 * json_free. On failure returns false, leaves `out` JSON_NULL, and
 * `*why_out` (optional) names the first violated rule as a static string. */
enum fleet_wiki_parse_status { FLEET_WIKI_PARSE_NOT_ENTRY,
    FLEET_WIKI_PARSE_ENTRY, FLEET_WIKI_PARSE_ALLOC_FAILED };
enum fleet_wiki_parse_status fleet_wiki_entry_parse_checked(
    const char *, size_t, struct json_value *, const char **);

bool fleet_wiki_entry_parse(const char *text, size_t len,
                            struct json_value *out, const char **why_out);

/* True when `needle` is a substring of the entry's topic, summary, any
 * applies_to string, or any lesson rule or why. Case is folded for ASCII
 * letters only. An empty needle matches every entry. */
bool fleet_wiki_entry_matches(const struct json_value *entry,
                              const char *needle);

#define FLEET_WIKI_MATCH_FIELDS 6
/* Names the fields of `entry` (and `slug`, when non-NULL) that contain
 * `needle`, in the fixed order slug, topic, summary, applies_to, rule, why.
 * Writes static strings to `out` and returns their count; an empty needle
 * yields 0. */
size_t fleet_wiki_entry_matched_fields(const struct json_value *entry,
    const char *slug, const char *needle, const char *out[FLEET_WIKI_MATCH_FIELDS]);

struct fleet_wiki_entry_query {
    const char *q;
    const char *topic;
    const char *applies_to;
    /* page slug of the row being tested; q also matches it (NULL or empty: not searched) */
    const char *slug;
};
bool fleet_wiki_entry_query_matches(const struct json_value *,
    const struct fleet_wiki_entry_query *);


/* Signed review bodies remain ordinary WIKI ledger objects. The host signing
 * key is the reviewer; an agent label is descriptive, with no Sybil resistance,
 * reputation, permission or execution authority. Targets never follow a slug. */
#define FLEET_WIKI_REVIEW_SCHEMA "zcl.fleet_wiki_review.v1"
enum fleet_wiki_review_status {
    FLEET_WIKI_NOT_REVIEW, FLEET_WIKI_REVIEW_VALID,
    FLEET_WIKI_REVIEW_INVALID, FLEET_WIKI_REVIEW_ALLOC_FAILED
};
/* Valid output owns a JSON object; all other outputs are JSON_NULL.
 * verdict: approve/request-changes/comment; optional integer rating: 1..5;
 * rationale: 1..1000 printable UTF-8 bytes; target: canonical exact id. */
enum fleet_wiki_review_status fleet_wiki_review_parse(
    const char *, size_t, struct json_value *, const char **);

#endif
