/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_code_have — the gate on "does this checkout already do X?".
 *
 * This group exists because of a specific, expensive failure. This tree
 * already had a 970-line ActiveRecord layer with sixteen validation macros
 * used by most of its models. An agent asked to add validation searched for
 * "validation", found nothing (the macros are named `validates_*`), and
 * imported a 12,474-line ORM from another project. Case 1 below is the direct
 * regression test for that: `code have` for "validation" must reach
 * `engine/models/include/models/activerecord.h`.
 *
 * Coverage:
 *   1. REAL TREE  — "validation" finds the ActiveRecord macros, and the
 *                   reported use count is not fabricated (cross-checked
 *                   against the ref index for one named symbol).
 *   2. fixture    — used_by_files is EXACT and excludes comment-only mentions.
 *   3. fixture    — a genuinely absent capability answers NOT FOUND, not a
 *                   weak match.
 *   4. verdict    — derived only from the rendered evidence; a zero-caller
 *                   record can never read ALREADY EXISTS.
 *   5. stemming   — the morphology that makes "validation" reach `validates_*`.
 *   6. freshness  — the cached index answers identically warm, and after a
 *                   source file changes it does NOT serve the stale answer.
 *   7. purpose    — a purpose past the old field is stored WHOLE, and
 *                   an over-long one is still visibly marked (fail loud).
 *   8. rejection  — a wrong input key names the keys the leaf accepts.
 *
 * Scratch work happens under ./test-tmp/ (project no-/tmp convention). */

#include "test/test_core.h"

#include "base/text_fit.h"
#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "codeindex/codeindex_capability.h"
#include "json/json.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

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

/* A purpose above the OLD 160-byte field and below the new one. It must be
 * stored WHOLE — this is the regression on the truncation that both spammed
 * WARN lines and ate the end of every long purpose. */
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

int test_code_have(void)
{
    int failures = 0;
    struct ci_capability caps[8];
    struct ci_capability_query q;

    /* ── 5: the morphology, first — everything else rests on it ───────── */
    {
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
    }

    /* ── 4: the verdict is derived from the rendered evidence ─────────── */
    {
        struct ci_capability c;
        struct ci_capability_query vq;
        memset(&c, 0, sizeof(c));
        memset(&vq, 0, sizeof(vq));
        vq.term_count = 1;
        c.terms_matched = 1;
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
    }

    /* ── 8: a wrong input key names the keys the leaf accepts ─────────── */
    {
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
    }

    /* ── 1: the real tree — the regression this group exists for ──────── */
    {
        struct codeindex *ci = codeindex_open_source_view(".");
        CH_CHECK("the checkout's own index opens", ci != NULL);
        if (ci) {
            int n = codeindex_capabilities(ci, "validation", caps, 8, &q);
            int at = n > 0 ? ch_find(caps, n,
                                     "engine/models/include/models/activerecord.h")
                           : -1;
            CH_CHECK("`code have validation` reaches the ActiveRecord macros",
                     at >= 0);
            if (at >= 0) {
                /* Every listed name must actually carry the concept — the
                 * list is alphabetical, so it opens on the AR_*_VALIDATE
                 * helpers rather than on validates_*, and asserting a
                 * particular head would be asserting sort order, not
                 * relevance. */
                bool all_relevant = caps[at].symbols_listed > 0;
                for (int k = 0; k < caps[at].symbols_listed; k++) {
                    char low[128];
                    size_t li = 0;
                    for (; caps[at].symbols[k][li] && li + 1 < sizeof(low); li++)
                        low[li] = (char)tolower(
                            (unsigned char)caps[at].symbols[k][li]);
                    low[li] = '\0';
                    if (!strstr(low, "valid")) all_relevant = false;
                }
                CH_CHECK("every listed symbol carries the queried concept",
                         all_relevant);
                CH_CHECK("the matched set is the whole validation surface",
                         caps[at].symbol_count >= 16);
                /* And the specific macro family the failed lane needed is in
                 * that anchor — the fact this whole group exists for. */
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
                         caps[at].used_by_files >= 40);
                CH_CHECK("the count says what it counted",
                         strcmp(caps[at].count_basis,
                                CI_CAPABILITY_BASIS_MATCHED) == 0);

                /* Not fabricated: the capability's count must be at least the
                 * count for ONE of its symbols, taken independently from the
                 * ref index. */
                static struct ci_ref refs[512];
                int nr = codeindex_refs(ci, "validates_presence_of", refs,
                                        (int)(sizeof(refs) / sizeof(refs[0])));
                char last[256] = "";
                int distinct = 0;
                for (int i = 0; i < nr; i++) {
                    if (strcmp(refs[i].ref_file, last) != 0) {
                        distinct++;
                        snprintf(last, sizeof(last), "%s", refs[i].ref_file);
                    }
                }
                CH_CHECK("the use count is consistent with the ref index",
                         distinct > 0 && caps[at].used_by_files >= distinct);
            }
            CH_CHECK("the verdict on a live capability is ALREADY EXISTS",
                     n > 0 && codeindex_capability_verdict(caps, n, &q) ==
                                  CI_CAPABILITY_ALREADY_EXISTS);
            codeindex_close(ci);
        }
    }

    /* ── 2, 3, 6, 7: the hermetic fixture ─────────────────────────────── */
    system("rm -rf " HAVE_FIX);
    if (!ch_write_fixture(false)) {
        printf("  code_have: write_fixture... FAIL\n");
        return failures + 1;
    }

    struct codeindex *fx = codeindex_open_source_view(HAVE_FIX);
    CH_CHECK("fixture index builds", fx != NULL);
    if (!fx) return failures + 1;

    /* 7: purpose capacity, measured against real stored text. */
    {
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
    }

    /* 2: used_by_files is exact and excludes comment-only mentions. */
    int n = codeindex_capabilities(fx, "validation", caps, 8, &q);
    int at = n > 0 ? ch_find(caps, n, "engine/models/include/models/arfix.h") : -1;
    CH_CHECK("the fixture capability is found by concept, not by name",
             at >= 0);
    if (at >= 0) {
        CH_CHECK("it lists all three macros",
                 caps[at].symbol_count == 3 && caps[at].symbols_listed == 3);
        CH_CHECK("used_by_files counts the 5 callers and NOT the 2 mentions",
                 caps[at].used_by_files == CH_CALLERS);
        CH_CHECK("an example caller is named",
                 caps[at].example_caller[0] != '\0' &&
                 strstr(caps[at].example_caller, "engine/models/src/") != NULL);
        CH_CHECK("the fixture verdict is ALREADY EXISTS",
                 codeindex_capability_verdict(caps, n, &q) ==
                     CI_CAPABILITY_ALREADY_EXISTS);
    }

    /* 3: genuinely absent capability. */
    {
        int an = codeindex_capabilities(fx, "quantum teleportation choreography",
                                        caps, 8, &q);
        CH_CHECK("an absent capability returns no weak match", an == 0);
        CH_CHECK("an absent capability is NOT FOUND",
                 codeindex_capability_verdict(caps, an, &q) ==
                     CI_CAPABILITY_NOT_FOUND);
        CH_CHECK("a NOT FOUND still reports what it searched for",
                 q.term_count == 3 && strcmp(q.stems[0], "quantum") == 0);
    }

    /* 6a: the warm (cached) answer equals the cold one. */
    {
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
    }
    codeindex_close(fx);

    /* 6b: THE ONE THAT MATTERS. Add a sixth caller and reopen. A cache that
     * confidently serves the old count is worse than no cache at all — it
     * would answer "we do not have that" about code somebody just wrote. */
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

    system("rm -rf " HAVE_FIX);
    return failures;
}
