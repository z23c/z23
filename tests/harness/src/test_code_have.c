/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_code_have: the gate on "does this checkout already do X?".
 *
 * Case 1: `code have` for "validation" must reach
 * `engine/models/include/models/activerecord.h` (the ActiveRecord
 * `validates_*` macros).
 *
 * Coverage:
 *   1. real tree  - "validation" finds the ActiveRecord macros; the use count
 *                   is cross-checked against the ref index for one symbol.
 *   2. fixture    - used_by_files is exact and excludes comment-only mentions.
 *   3. fixture    - an absent capability answers NOT FOUND, not a weak match.
 *   4. verdict    - derived from the rendered evidence; a zero-caller record
 *                   never reads ALREADY EXISTS.
 *   5. stemming   - "validation" reaches `validates_*`.
 *   6. freshness  - the cached index answers identically warm, and does not
 *                   serve a stale answer after a source change.
 *   7. purpose    - a long purpose is stored whole; an over-long one is
 *                   visibly marked.
 *   8. rejection  - a wrong input key names the keys the leaf accepts.
 *
 * Scratch work happens under ./test-tmp/ (project no-/tmp convention). */

#include "test/test_core.h"

#include "base/text_fit.h"
#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "../../../cognition/modules/codeindex/src/codeindex_priv.h"
#include <sqlite3.h>
#include "codeindex/codeindex_capability.h"
#include "json/json.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define CH_CHECK(name, expr) do {                                      \
    if (expr) { printf("  code_have: %s... OK\n", (name)); }           \
    else { printf("  code_have: %s... FAIL\n", (name)); failures++; }  \
} while (0)

#define HAVE_FIX "test-tmp/ci_have"

/* Write content to <dir>/<rel>, creating parent dirs (mirrors test_codeindex). */
static bool ch_write(const char *dir, const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    if (content && content[0]) fwrite(content, 1, strlen(content), f);
    fclose(f);
    return true;
}

/* ── the fixture: a validation capability with a KNOWN caller count ─────
 *
 * Five files invoke a macro. Two more merely NAME one in a comment. The
 * difference is the whole point of `used_by_files`: a mention is not a use,
 * and a count that cannot tell them apart cannot tell a live capability from
 * an abandoned one. */

static const char *ARFIX_H =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * purpose: record validation macros for the fixture model layer.\n"
    " */\n"
    "#ifndef ARFIX_H\n"
    "#define ARFIX_H\n"
    "/* Fail the record when the field is empty. */\n"
    "#define arfix_validates_presence(rec, field) ((void)(rec))\n"
    "/* Fail the record when the field is out of range. */\n"
    "#define arfix_validates_range(rec, field, lo, hi) ((void)(rec))\n"
    "/* Fail the record when the field is the wrong length. */\n"
    "#define arfix_validates_length(rec, field, n) ((void)(rec))\n"
    "#endif\n";

/* A caller: invokes the macros for real. */
static const char *MODEL_USER_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * A fixture model that runs the validation lifecycle.\n"
    " */\n"
    "#include \"models/arfix.h\"\n"
    "int %s_save(int rec)\n"
    "{\n"
    "    arfix_validates_presence(rec, id);\n"
    "    arfix_validates_range(rec, id, 0, 10);\n"
    "    return rec;\n"
    "}\n";

/* A non-caller: names a macro in prose only. */
static const char *MODEL_MENTION_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * A fixture model with no fields, so the arfix_validates_presence\n"
    " * lifecycle does not apply to it.\n"
    " */\n"
    "int %s_touch(int rec) { return rec; }\n";

/* Unrelated code, so the query has something to correctly ignore. */
static const char *NET_FOO_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * purpose: fixture socket plumbing, unrelated to records.\n"
    " */\n"
    "int foo_send(int fd) { return fd; }\n";

/* A purpose above the old 160-byte field and below the current one is stored
 * whole. */
#define PURPOSE_LONG_TEXT \
    "aaaaaaaaaa bbbbbbbbbb cccccccccc dddddddddd eeeeeeeeee " \
    "ffffffffff gggggggggg hhhhhhhhhh iiiiiiiiii jjjjjjjjjj kkkkkkkkkk " \
    "llllllllll mmmmmmmmmm nnnnnnnnnn oooooooooo pppppppppp qqqqqqqqqq " \
    "rrrrrrrrrr ssssssssss tttttttttt uuuuuuuuuu vvvvvvvvvv wwwwwwwwww"

static const char *PURPOSE_LONG_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * purpose: " PURPOSE_LONG_TEXT "\n"
    " */\n"
    "int purpose_long_fn(void) { return 0; }\n";

/* Far past the field: the cut must remain VISIBLE, not silently dropped. */
static const char *PURPOSE_HUGE_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * purpose: "
    "0123456789012345678901234567890123456789012345678901234567890123456789"
    "0123456789012345678901234567890123456789012345678901234567890123456789"
    "0123456789012345678901234567890123456789012345678901234567890123456789"
    "0123456789012345678901234567890123456789012345678901234567890123456789"
    "0123456789012345678901234567890123456789012345678901234567890123456789"
    "0123456789012345678901234567890123456789012345678901234567890123456789"
    "\n */\n"
    "int purpose_huge_fn(void) { return 0; }\n";

#define CH_CALLERS 5
#define CH_MENTIONS 2

static bool ch_write_mixed_fixture(void);

static bool ch_write_fixture(bool with_sixth_caller)
{
    if (!ch_write(HAVE_FIX, "engine/models/include/models/arfix.h", ARFIX_H))
        return false;
    static const char *const callers[] = { "alpha", "beta", "gamma", "delta",
                                           "epsilon", "zeta" };
    int n = with_sixth_caller ? CH_CALLERS + 1 : CH_CALLERS;
    for (int i = 0; i < n; i++) {
        char body[1024], rel[256];
        snprintf(body, sizeof(body), MODEL_USER_C, callers[i]);
        snprintf(rel, sizeof(rel), "engine/models/src/%s.c", callers[i]);
        if (!ch_write(HAVE_FIX, rel, body)) return false;
    }
    static const char *const mentions[] = { "eta", "theta" };
    for (int i = 0; i < CH_MENTIONS; i++) {
        char body[1024], rel[256];
        snprintf(body, sizeof(body), MODEL_MENTION_C, mentions[i]);
        snprintf(rel, sizeof(rel), "engine/models/src/%s.c", mentions[i]);
        if (!ch_write(HAVE_FIX, rel, body)) return false;
    }
    if (!ch_write(HAVE_FIX, "engine/models/include/models/scatter.h",
        "int quartz_event(void);\nint meridian_repair(void);\n/* quartz */\nint sunstone_repair(void);\n")) return false;
    for (int i = 0; i < 3; ++i) {
        char path[128], body[256];
        snprintf(path, sizeof(path), "engine/models/src/scatter%d.c", i);
        snprintf(body, sizeof(body), "#include \"models/scatter.h\"\nint use%d(void) { return quartz_event() + meridian_repair(); }\n", i);
        if (!ch_write(HAVE_FIX, path, body)) return false;
    }
    if (!ch_write_mixed_fixture()) return false;
    return ch_write(HAVE_FIX, "core/modules/net/src/foo.c", NET_FOO_C) &&
           ch_write(HAVE_FIX, "core/modules/net/src/purpose_long.c", PURPOSE_LONG_C) &&
           ch_write(HAVE_FIX, "core/modules/net/src/purpose_huge.c", PURPOSE_HUGE_C);
}

/* Index of the capability anchored on `header`, or -1. */
static int ch_find(const struct ci_capability *caps, int n, const char *header)
{
    for (int i = 0; i < n; i++)
        if (strcmp(caps[i].header, header) == 0) return i;
    return -1;
}

static bool ch_query_reaches(struct codeindex *ci, const char *query,
                             const char *path)
{
    struct ci_capability caps[5];
    struct ci_capability_query q;
    int n = codeindex_capabilities(ci, query, caps, 5, &q);
    return n > 0 && ch_find(caps, n, path) >= 0;
}

/* Run the morphology table: each query word must stem to the form that
 * reaches the code. */
static int ch_check_query_stemming(void)
{
    int failures = 0;
    struct { const char *in; const char *want; } cases[] = {
        { "validation", "valid" },   /* reaches validates_* AND validate_* */
        { "validations", "valid" },
        { "hashing", "hash" },
        { "records", "record" },
        { "logging", "log" },        /* -ing strip then doubled-consonant */
        { "scheduler", "schedul" },
        { "serialization", "serializ" },
        { "connection", "connect" },
        { "database", "database" },  /* no suffix to strip */
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char w[64];
        snprintf(w, sizeof(w), "%s", cases[i].in);
        ci_capability_stem(w);
        if (strcmp(w, cases[i].want) != 0) {
            printf("    stem('%s') = '%s', want '%s'\n", cases[i].in, w,
                   cases[i].want);
            ok = false;
        }
    }
    CH_CHECK("query stems reduce to the form that reaches the code", ok);
    return failures;
}

/* Exercise the verdict rules on a synthetic capability record. */
static int ch_check_verdict_derivation(void)
{
    int failures = 0;
    struct ci_capability c;
    struct ci_capability_query vq;
    memset(&c, 0, sizeof(c));
    memset(&vq, 0, sizeof(vq));
    vq.term_count = 1;
    c.terms_matched = 1;
    c.coherent_terms_matched = 1;
    c.coherent_used_by_files = 25;
    c.symbol_count = 4;

    /* Nothing calls it. However well it matched, it is not established. */
    c.used_by_files = 0;
    CH_CHECK("zero callers never reads ALREADY EXISTS",
             codeindex_capability_verdict(&c, 1, &vq) !=
                 CI_CAPABILITY_ALREADY_EXISTS);

    c.used_by_files = 25;
    CH_CHECK("matched terms + real callers reads ALREADY EXISTS",
             codeindex_capability_verdict(&c, 1, &vq) ==
                 CI_CAPABILITY_ALREADY_EXISTS);

    /* A search that had to drop a term answered a different question. */
    vq.relaxed = true;
    CH_CHECK("a relaxed search can never reach ALREADY EXISTS",
             codeindex_capability_verdict(&c, 1, &vq) ==
                 CI_CAPABILITY_PARTIAL);
    vq.relaxed = false;

    /* A file-level hit with no named API is PARTIAL, not an answer. */
    c.symbol_count = 0;
    CH_CHECK("no named symbol caps the verdict at PARTIAL",
             codeindex_capability_verdict(&c, 1, &vq) ==
                 CI_CAPABILITY_PARTIAL);

    CH_CHECK("an empty result set is NOT FOUND",
             codeindex_capability_verdict(NULL, 0, &vq) ==
                 CI_CAPABILITY_NOT_FOUND);
    CH_CHECK("verdict labels are the three documented strings",
             strcmp(codeindex_capability_verdict_label(
                        CI_CAPABILITY_ALREADY_EXISTS),
                    "ALREADY EXISTS") == 0 &&
             strcmp(codeindex_capability_verdict_label(
                        CI_CAPABILITY_PARTIAL), "PARTIAL") == 0 &&
             strcmp(codeindex_capability_verdict_label(
                        CI_CAPABILITY_NOT_FOUND), "NOT FOUND") == 0);
    return failures;
}

/* Feed code.have a wrong input key and inspect the refusal. */
static int ch_check_input_key_rejection(void)
{
    int failures = 0;
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(),
                                  "code.have", NULL);
    CH_CHECK("code.have is a registered leaf", spec != NULL);
    if (spec) {
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "query", "validation");
        char why[192] = { 0 };
        bool ok = zcl_command_registry_input_validate(spec, &input, why,
                                                      sizeof(why));
        char detail[512];
        (void)zcl_command_registry_input_reject_detail(spec, why, detail,
                                                       sizeof(detail));
        json_free(&input);
        CH_CHECK("a wrong input key is refused", !ok);
        CH_CHECK("the refusal names the offending key",
                 strstr(detail, "query") != NULL);
        CH_CHECK("the refusal names the ACCEPTED keys",
                 strstr(detail, "text") != NULL &&
                 strstr(detail, "limit") != NULL);
    }
    return failures;
}

/* True when the record lists at least one symbol and every listed symbol's
 * lowercased name contains "valid". */
static bool ch_symbols_all_carry_valid(const struct ci_capability *cap)
{
    bool all_relevant = cap->symbols_listed > 0;
    for (int k = 0; k < cap->symbols_listed; k++) {
        char low[128];
        size_t li = 0;
        for (; cap->symbols[k][li] && li + 1 < sizeof(low); li++)
            low[li] = (char)tolower((unsigned char)cap->symbols[k][li]);
        low[li] = '\0';
        if (!strstr(low, "valid")) all_relevant = false;
    }
    return all_relevant;
}

/* Count the distinct ref files the ref index reports for one symbol, reading
 * at most 512 refs. The index orders refs by (ref_file, ref_line), so equal
 * files are adjacent and a consecutive-duplicate check is exact within that
 * window; when a symbol has more than 512 refs the result is a lower bound.
 * A codeindex_refs error (negative count) yields 0 distinct files, which the
 * caller's "distinct > 0" check reports as a failure. */
static int ch_count_distinct_ref_files_capped(struct codeindex *ci,
                                              const char *symbol)
{
    static struct ci_ref refs[512];
    int nr = codeindex_refs(ci, symbol, refs,
                            (int)(sizeof(refs) / sizeof(refs[0])));
    char last[256] = "";
    int distinct = 0;
    for (int i = 0; i < nr; i++) {
        if (strcmp(refs[i].ref_file, last) != 0) {
            distinct++;
            snprintf(last, sizeof(last), "%s", refs[i].ref_file);
        }
    }
    return distinct;
}

/* Check one real-tree capability record: listed symbols, anchor symbol and
 * the use-count cross-check. */
static int ch_check_real_capability_evidence(struct codeindex *ci,
                                             struct ci_capability *cap)
{
    int failures = 0;
    /* Every listed name must actually carry the concept — the
     * list is alphabetical, so it opens on the AR_*_VALIDATE
     * helpers rather than on validates_*, and asserting a
     * particular head would be asserting sort order, not
     * relevance. */
    CH_CHECK("every listed symbol carries the queried concept",
             ch_symbols_all_carry_valid(cap));
    CH_CHECK("the matched set is the whole validation surface",
             cap->symbol_count >= 16);
    /* the anchor also carries the macro family */
    struct ci_symbol vs;
    bool vfound = false;
    codeindex_symbol(ci, "validates_presence_of", &vs, &vfound);
    CH_CHECK("validates_presence_of belongs to that header",
             vfound &&
             (strcmp(vs.def_path,
                     "engine/models/include/models/activerecord.h") == 0 ||
              strcmp(vs.decl_path,
                     "engine/models/include/models/activerecord.h") == 0));
    /* The count is a floor, not a pin: adding a model may only
     * raise it. A baseline may shrink only when the codebase
     * does, and then this line is the thing that should be
     * re-derived by hand rather than lowered by reflex. */
    CH_CHECK("its use count reflects a load-bearing capability",
             cap->used_by_files >= 40);
    CH_CHECK("the count says what it counted",
             strcmp(cap->count_basis,
                    CI_CAPABILITY_BASIS_MATCHED) == 0);

    /* Not fabricated: the capability's count must be at least the
     * count for ONE of its symbols, taken independently from the
     * ref index. */
    int distinct = ch_count_distinct_ref_files_capped(ci,
                                                      "validates_presence_of");
    CH_CHECK("the use count is consistent with the ref index",
             distinct > 0 && cap->used_by_files >= distinct);
    return failures;
}

/* Open the checkout's own index and check its validation capability. */
static int ch_check_real_tree(struct ci_capability *caps,
                              struct ci_capability_query *q)
{
    int failures = 0;
    struct codeindex *ci = codeindex_open_source_view(".");
    CH_CHECK("the checkout's own index opens", ci != NULL);
    if (ci) {
        int n = codeindex_capabilities(ci, "validation", caps, 8, q);
        int at = n > 0 ? ch_find(caps, n,
                                 "engine/models/include/models/activerecord.h")
                       : -1;
        CH_CHECK("`code have validation` reaches the ActiveRecord macros",
                 at >= 0);
        if (at >= 0) {
            failures += ch_check_real_capability_evidence(ci, &caps[at]);
        }
        CH_CHECK("the verdict on a live capability is ALREADY EXISTS",
                 n > 0 && codeindex_capability_verdict(caps, n, q) ==
                     CI_CAPABILITY_ALREADY_EXISTS);
        struct ci_capability pack[5];
        struct ci_capability_query pack_q;
        int pack_n = codeindex_capabilities(
            ci, "how is a plugin packed into an archive", pack, 5, &pack_q);
        bool pack_found = false;
        for (int i = 0; i < pack_n; i++)
            if (strcmp(pack[i].header,
                       "contexts/commons/modules/plugin/src/plugin_pack.c") == 0)
                pack_found = true;
        CH_CHECK("a multi-term filename reaches its implementation",
                 pack_found);
        struct ci_capability base58[5];
        struct ci_capability_query base58_q;
        int base58_n = codeindex_capabilities(
            ci, "Base58 address encoding", base58, 5, &base58_q);
        bool base58_found = false;
        for (int i = 0; i < base58_n; i++)
            if (strcmp(base58[i].header,
                       "platform/domain/encoding/src/base58.c") == 0)
                base58_found = true;
        CH_CHECK("Base58 address encoding reaches its codec",
                 base58_found);
        struct ci_capability bech32[5];
        struct ci_capability_query bech32_q;
        int bech32_n = codeindex_capabilities(
            ci, "how addresses get a checksum so typos are caught", bech32, 5,
            &bech32_q);
        bool bech32_found = false;
        for (int i = 0; i < bech32_n; i++)
            if (strcmp(bech32[i].header,
                       "platform/domain/encoding/src/bech32.c") == 0)
                bech32_found = true;
        CH_CHECK("the address checksum query reaches its Bech32 codec",
                 bech32_found);
        CH_CHECK("the changed-test query reaches its selector command",
                 ch_query_reaches(ci, "what decides which tests run for my change",
                                  "tools/command/native_dev_verify_change_command.c"));
        CH_CHECK("the rebuild-selection query reaches its harness code",
                 ch_query_reaches(ci, "which harness code picks the test groups that need rebuilding after a change",
                                  "tests/harness/src/selection_build_needs.c"));
        CH_CHECK("the cache-reason query reaches its explanation code",
                 ch_query_reaches(ci, "where is the code that explains why a test cache entry was hit or missed",
                                  "tests/harness/src/testcache_reason.c"));
        CH_CHECK("the existing-feature query reaches the code-have command",
                 ch_query_reaches(ci, "how do I see whether a feature already exists before I write it again",
                                  "tools/command/native_code_have_command.c"));
        CH_CHECK("the index-word query reaches its text search",
                 ch_query_reaches(ci, "how does the text search over the code index match words",
                                  "tools/command/native_dev_index_search.c"));
        CH_CHECK("the tangled-function query reaches its complexity check",
                 ch_query_reaches(ci, "which check tells me my function has grown too tangled to maintain",
                                  "tools/command/native_dev_cx_check.c"));
        CH_CHECK("the accepted-work query reaches its shared fixture",
                 ch_query_reaches(ci, "shared fixture setup for accepted work acceptance tests",
                                  "tests/harness/src/accepted_work_fixture.c"));
        struct ci_capability android[5];
        struct ci_capability_query android_q;
        int android_n = codeindex_capabilities(
            ci, "Android app entry point for the Z23 node", android, 5,
            &android_q);
        bool android_found = false;
        for (int i = 0; i < android_n; i++)
            if (strcmp(android[i].header,
                       "apps/z23android/android_main.c") == 0)
                android_found = true;
        CH_CHECK("the Android entry-point query reaches its app",
                 android_found);
        struct ci_capability ledger[5];
        struct ci_capability_query ledger_q;
        int ledger_n = codeindex_capabilities(
            ci, "device review screen that shows a ledger transaction before signing",
            ledger, 5, &ledger_q);
        bool ledger_found = false;
        for (int i = 0; i < ledger_n; i++)
            if (strcmp(ledger[i].header,
                       "apps/zcl-ledger/src/zcl_tx_review.c") == 0)
                ledger_found = true;
        CH_CHECK("the Ledger device review query reaches its transaction parser",
                 ledger_found);
        codeindex_close(ci);
    }
    return failures;
}

/* Check purpose storage on the fixture: a long purpose stored whole, an
 * over-long one visibly cut. */
static int ch_check_purpose_capacity(struct codeindex *fx)
{
    int failures = 0;
    struct ci_file f;
    bool found = false;
    bool ok = codeindex_file(fx, "core/modules/net/src/purpose_long.c", &f, &found);
    CH_CHECK("a purpose past the OLD 160-byte field is stored WHOLE",
             ok && found && strlen(PURPOSE_LONG_TEXT) > 160 &&
             strcmp(f.purpose, PURPOSE_LONG_TEXT) == 0 &&
             strstr(f.purpose, ZCL_TEXT_FIT_MARKER_TAG) == NULL);
    found = false;
    ok = codeindex_file(fx, "core/modules/net/src/purpose_huge.c", &f, &found);
    CH_CHECK("a purpose past the field is still VISIBLY cut",
             ok && found &&
             strstr(f.purpose, ZCL_TEXT_FIT_MARKER_TAG) != NULL);
    return failures;
}

/* Check the fixture capability's symbol list, caller count, example caller
 * and verdict. */
static int ch_check_fixture_capability_counts(struct ci_capability *caps,
                                              int n,
                                              struct ci_capability_query *q,
                                              int at)
{
    int failures = 0;
    CH_CHECK("it lists all three macros",
             caps[at].symbol_count == 3 && caps[at].symbols_listed == 3);
    CH_CHECK("used_by_files counts the 5 callers and NOT the 2 mentions",
             caps[at].used_by_files == CH_CALLERS);
    CH_CHECK("an example caller is named",
             caps[at].example_caller[0] != '\0' &&
             strstr(caps[at].example_caller, "engine/models/src/") != NULL);
    CH_CHECK("the fixture verdict is ALREADY EXISTS",
             codeindex_capability_verdict(caps, n, q) ==
                 CI_CAPABILITY_ALREADY_EXISTS);
    return failures;
}

/* Query the fixture for a capability that is genuinely absent. */
static int ch_check_absent_capability(struct codeindex *fx,
                                      struct ci_capability *caps,
                                      struct ci_capability_query *q)
{
    int failures = 0;
    int an = codeindex_capabilities(fx, "quantum teleportation choreography",
                                    caps, 8, q);
    CH_CHECK("an absent capability returns no weak match", an == 0);
    CH_CHECK("an absent capability is NOT FOUND",
             codeindex_capability_verdict(caps, an, q) ==
                 CI_CAPABILITY_NOT_FOUND);
    CH_CHECK("a NOT FOUND still reports what it searched for",
             q->term_count == 3 && strcmp(q->stems[0], "quantum") == 0);
    return failures;
}

/* Reopen the fixture index warm and require the same answer as the cold
 * one. */
static int ch_check_cached_answer_matches(const struct ci_capability *caps,
                                          int n, int at)
{
    int failures = 0;
    struct codeindex *warm = codeindex_open_source_view(HAVE_FIX);
    struct ci_capability wcaps[8];
    struct ci_capability_query wq;
    int wn = warm ? codeindex_capabilities(warm, "validation", wcaps, 8, &wq)
                  : -1;
    int wat = wn > 0 ? ch_find(wcaps, wn,
                               "engine/models/include/models/arfix.h") : -1;
    CH_CHECK("the cached index answers identically",
             warm && wn == n && wat == at && at >= 0 &&
             wcaps[wat].used_by_files == caps[at].used_by_files &&
             wcaps[wat].symbol_count == caps[at].symbol_count);
    if (warm) codeindex_close(warm);
    return failures;
}

static int ch_check_coherence(struct codeindex *fx, struct ci_capability *caps,
                              struct ci_capability_query *q);
static int ch_check_coherence_positive(struct codeindex *fx, struct ci_capability *caps,
                                       struct ci_capability_query *q);
static bool ch_paired_header_ownership(struct codeindex *ci);

/* Run the hermetic-fixture checks: purpose capacity, the capability's
 * counts, absence and warm-cache agreement. */
static int ch_check_hermetic_fixture(struct codeindex *fx,
                                     struct ci_capability *caps,
                                     struct ci_capability_query *q)
{
    int failures = 0;

    /* 7: purpose capacity, measured against real stored text. */
    failures += ch_check_purpose_capacity(fx);

    /* 2: used_by_files is exact and excludes comment-only mentions. */
    int n = codeindex_capabilities(fx, "validation", caps, 8, q);
    int at = n > 0 ? ch_find(caps, n, "engine/models/include/models/arfix.h") : -1;
    CH_CHECK("the fixture capability is found by concept, not by name",
             at >= 0);
    if (at >= 0) {
        failures += ch_check_fixture_capability_counts(caps, n, q, at);
    }

    /* 3: genuinely absent capability. */
    failures += ch_check_absent_capability(fx, caps, q);

    /* 6a: the warm (cached) answer equals the cold one. */
    failures += ch_check_cached_answer_matches(caps, n, at);

    failures += ch_check_coherence(fx, caps, q);
    return failures;
}

static int ch_check_coherence(struct codeindex *fx, struct ci_capability *caps,
                              struct ci_capability_query *q)
{
    int failures = 0;
    int scattered = codeindex_capabilities(fx, "quartz meridian", caps, 8, q);
    int sat = scattered > 0 ? ch_find(caps, scattered, "engine/models/include/models/scatter.h") : -1;
    CH_CHECK("unrelated symbols retain counts without asserting completeness",
             sat >= 0 && caps[sat].terms_matched == 2 &&
             caps[sat].coherent_terms_matched == 1 && caps[sat].used_by_files == 3 &&
             codeindex_capability_verdict(caps, scattered, q) != CI_CAPABILITY_ALREADY_EXISTS);
    int unrelated = codeindex_capabilities(fx, "quartz sunstone", caps, 8, q);
    int uat = unrelated > 0 ? ch_find(caps, unrelated, "engine/models/include/models/scatter.h") : -1;
    CH_CHECK("uncalled coherent symbol cannot borrow callers",
             uat >= 0 && caps[uat].coherent_terms_matched == 2 &&
             caps[uat].used_by_files == 3 && caps[uat].coherent_used_by_files == 0 &&
             codeindex_capability_verdict(caps, unrelated, q) != CI_CAPABILITY_ALREADY_EXISTS);
    failures += ch_check_coherence_positive(fx, caps, q);
    return failures;
}

static int ch_check_coherence_positive(struct codeindex *fx, struct ci_capability *caps,
                                       struct ci_capability_query *q)
{
    int failures = 0;
    int positive = codeindex_capabilities(fx, "quartz event", caps, 8, q);
    int pat = positive > 0 ? ch_find(caps, positive, "engine/models/include/models/scatter.h") : -1;
    CH_CHECK("called coherent symbol supports high confidence",
             pat >= 0 && caps[pat].coherent_terms_matched == 2 &&
             caps[pat].coherent_used_by_files == 3 &&
             codeindex_capability_verdict(caps, positive, q) == CI_CAPABILITY_ALREADY_EXISTS);
    CH_CHECK("paired metadata cannot borrow header-owned callers",
             ch_paired_header_ownership(fx));
    return failures;
}


static bool ch_write_mixed_fixture(void)
{
    if (!ch_write(HAVE_FIX, "engine/models/include/models/mixed.h", "int zircon_amber_public(void);\n") ||
        !ch_write(HAVE_FIX, "engine/models/src/mixed.c", "#include \"models/mixed.h\"\nint zircon_amber_public(void) { return 1; }\nstatic int zircon_amber_private(void) { return 0; }\n")) return false;
    for (int i = 0; i < 3; ++i) {
        char path[128], body[256];
        snprintf(path, sizeof(path), "engine/models/src/mixeduser%d.c", i);
        snprintf(body, sizeof(body), "#include \"models/mixed.h\"\nint use_mixed%d(void) { return zircon_amber_public(); }\n", i);
        if (!ch_write(HAVE_FIX, path, body)) return false;
    }
    return true;
}


static bool ch_paired_query(struct codeindex *ci, struct ci_store *store)
{
    struct codeindex copy = *ci; copy.store = store;
    struct ci_capability caps[8];
    struct ci_capability_query q;
    int count = codeindex_capabilities(&copy, "zircon amber", caps, 8, &q);
    int at = count > 0 ? ch_find(caps, count, "engine/models/src/mixed.c") : -1;
    return at >= 0 && caps[at].coherent_terms_matched == 2 &&
           caps[at].coherent_used_by_files == 0 &&
           strcmp(codeindex_capability_confidence(&caps[at], &q), "high");
}

/* Exercise legal paired metadata in a private copy of the scanned index. */
static bool ch_paired_header_ownership(struct codeindex *ci)
{
    struct ci_store *store = ci_store_open_path(":memory:");
    if (!store) return false;
    sqlite3 *db = ci_store_db(store);
    sqlite3_backup *backup = sqlite3_backup_init(db, "main", ci_store_db(ci->store), "main");
    bool ok = backup && sqlite3_backup_step(backup, -1) == SQLITE_DONE;
    if (backup && sqlite3_backup_finish(backup) != SQLITE_OK) ok = false;
    struct ci_symbol rows[32];
    int n = ok ? ci_store_symbols_in_file(store, "engine/models/src/mixed.c", rows, 32) : 0;
    bool found = false;
    for (int i = 0; i < n && i < 32; ++i) {
        if (strcmp(rows[i].name, "zircon_amber_public")) continue;
        ok = sqlite3_exec(db, "DELETE FROM symbols WHERE name='zircon_amber_public' AND def_path='engine/models/src/mixed.c'", NULL, NULL, NULL) == SQLITE_OK;
        snprintf(rows[i].decl_path, sizeof(rows[i].decl_path), "%s", "engine/models/include/models/mixed.h");
        ok = ok && ci_store_put_symbol(store, &rows[i]);
        found = true;
        break;
    }
    ok = ok && found && ch_paired_query(ci, store);
    ci_store_close(store);
    return ok;
}

/* ── known-answer fixture: real questions, real files ──────────────────
 *
 * tests/fixtures/code_have/cases.jsonl holds one {"q":..,"answers":[..]} per
 * line. A case is a hit when any of the first HAVE_TOPK results equals an
 * answer or lies under an answer prefix. The suite passes when the hit rate
 * reaches HAVE_MIN_HIT_PERCENT; raise the constant as the ranker improves,
 * never lower it to admit a regression. */
#define HAVE_CASES_PATH   "tests/fixtures/code_have/cases.jsonl"
#define HAVE_TOPK         5
#define HAVE_MIN_HIT_PERCENT 49 /* of all cases: 33/63 (52%) on 2026-11-21, kept 2 hits of slack for path renames; ratchet up as lanes land */

static bool ch_path_answers(const char *path, const struct json_value *answers)
{
    for (size_t i = 0; i < json_size(answers); i++) {
        const char *a = json_get_str(json_at(answers, i));
        if (a && a[0] && strncmp(path, a, strlen(a)) == 0) return true;
    }
    return false;
}

static bool ch_case_hit(struct codeindex *ci, const char *line, size_t len,
                        double *ms)
{
    struct json_value v;
    json_init(&v);
    bool hit = false;
    if (json_read(&v, line, len)) {
        const char *qtext = json_get_str(json_get(&v, "q"));
        const struct json_value *answers = json_get(&v, "answers");
        struct ci_capability caps[HAVE_TOPK];
        struct ci_capability_query q;
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int n = qtext ? codeindex_capabilities(ci, qtext, caps, HAVE_TOPK, &q)
                      : 0;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        *ms = (double)(t1.tv_sec - t0.tv_sec) * 1e3 +
              (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
        for (int i = 0; i < n && answers; i++)
            if (ch_path_answers(caps[i].header, answers)) hit = true;
        printf("  code_have: case %-34s %s %.0f ms (top: %s)\n",
               qtext ? qtext : "?", hit ? "HIT " : "MISS", *ms,
               n > 0 ? caps[0].header : "-");
    }
    json_free(&v);
    return hit;
}

static int ch_check_known_answers(void)
{
    int failures = 0;
    struct codeindex *ci = codeindex_open_source_view(".");
    FILE *f = fopen(HAVE_CASES_PATH, "rb");
    CH_CHECK("known-answer cases open", f != NULL);
    CH_CHECK("the checkout's own index opens for the cases", ci != NULL);
    if (!f || !ci) {
        if (f) fclose(f);
        if (ci) codeindex_close(ci);
        return failures + 1;
    }
    char line[2048];
    int cases = 0, hits = 0, code_cases = 0, code_hits = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len < 3) continue;
        double ms = 0;
        bool docs = strstr(line, "\"answers\":[\"docs/") != NULL;
        bool hit = ch_case_hit(ci, line, len, &ms);
        cases++;
        hits += hit ? 1 : 0;
        if (!docs) { code_cases++; code_hits += hit ? 1 : 0; }
    }
    fclose(f);
    codeindex_close(ci);
    printf("  code_have: known-answer top-%d hit rate all %d/%d, non-docs "
           "%d/%d\n", HAVE_TOPK, hits, cases, code_hits, code_cases);
    CH_CHECK("known-answer top-5 hit rate meets the threshold",
             cases > 0 && hits * 100 >= cases * HAVE_MIN_HIT_PERCENT);
    return failures;
}

int test_code_have(void)
{
    int failures = 0;
    struct ci_capability caps[8];
    struct ci_capability_query q;

    /* ── 5: the morphology, first — everything else rests on it ───────── */
    failures += ch_check_query_stemming();

    /* ── 4: the verdict is derived from the rendered evidence ─────────── */
    failures += ch_check_verdict_derivation();

    /* ── 8: a wrong input key names the keys the leaf accepts ─────────── */
    failures += ch_check_input_key_rejection();

    /* ── 1: the real tree ──────── */
    failures += ch_check_real_tree(caps, &q);
    failures += ch_check_known_answers();

    /* ── 2, 3, 6, 7: the hermetic fixture ─────────────────────────────── */
 TEST_DISCARD(system("rm -rf " HAVE_FIX));
    if (!ch_write_fixture(false)) {
        printf("  code_have: write_fixture... FAIL\n");
        return failures + 1;
    }

    struct codeindex *fx = codeindex_open_source_view(HAVE_FIX);
    CH_CHECK("fixture index builds", fx != NULL);
    if (!fx) return failures + 1;

    failures += ch_check_hermetic_fixture(fx, caps, &q);
    codeindex_close(fx);

    /* 6b: after adding a sixth caller and reopening, the stale count must not
     * be served. */
    {
        if (!ch_write_fixture(true)) {
            printf("  code_have: rewrite_fixture... FAIL\n");
            return failures + 1;
        }
        struct codeindex *after = codeindex_open_source_view(HAVE_FIX);
        struct ci_capability acaps[8];
        struct ci_capability_query aq;
        int an = after ? codeindex_capabilities(after, "validation", acaps, 8,
                                                &aq)
                       : -1;
        int aat = an > 0 ? ch_find(acaps, an,
                                   "engine/models/include/models/arfix.h") : -1;
        CH_CHECK("a changed source file is NOT answered from the stale index",
                 aat >= 0 && acaps[aat].used_by_files == CH_CALLERS + 1);
        if (after) codeindex_close(after);
    }

 TEST_DISCARD(system("rm -rf " HAVE_FIX));
    return failures;
}
