/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_telemetry_render — the generated snapshot/descriptor machinery and the
 * one renderer that turns it into JSON.
 *
 * These checks are not "does it emit a document". They pin the four properties
 * the layer exists to guarantee, each of which is a real defect class it
 * replaces:
 *
 *   omission is impossible   a leaf nobody wrote still renders its key, as
 *                            null, counted as a provider defect — never a
 *                            plausible 0 and never a missing key.
 *   unreadable != broken     a leaf we could not read is judged UNKNOWN, not
 *                            UNHEALTHY — the evaluator bug fixed in
 *                            telemetry_field_evaluate, where a JSON null read
 *                            as a false bool and drove a domain critical on a
 *                            missed read.
 *   views prune output only  every leaf is judged on every call, so a summary
 *                            view can never report ok over a broken full-tier
 *                            leaf.
 *   offsets are proved       a descriptor that would read past snapshot_size is
 *                            refused, not read.
 *   partial is a failure     a reply that lost a section returns false, never
 *                            a short document that reads like a healthy one.
 *
 * Node-free by construction: no datadir, no database, no lock. Nothing here
 * needs SetDataDir because nothing here opens a file. */

#include "test/test_core.h"

#include "json/json.h"
#include "util/telemetry_ontology.h"
#include "util/telemetry_render.h"
#include "util/telemetry_reply.h"
#include "util/telemetry_snapshots.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* One label-free assertion per line — same reason as test_telemetry_ontology:
 * TEST/ASSERT mint a per-function `_test_next` label, and these checks are
 * numerous, independent, and more useful reported individually. */
#define TR_CHECK(name, cond) \
    do { \
        printf("%s... ", (name)); \
        if (cond) { printf("OK\n"); } \
        else { printf("FAIL (%s)\n", #cond); failures++; } \
    } while (0)

/* A zeroed, maximally-aligned scratch snapshot for the walk-every-domain
 * checks: the descriptor tables address it by byte offset, so it must be
 * aligned for any member type a field table can declare. */
static union {
    max_align_t align;
    unsigned char bytes[1u << 16];
} g_scratch;

static const struct json_value *dig2(const struct json_value *o,
                                     const char *a, const char *b)
{
    return json_get(json_get(o, a), b);
}

static const struct json_value *dig3(const struct json_value *o,
                                     const char *a, const char *b,
                                     const char *c)
{
    return json_get(dig2(o, a, b), c);
}

/* ── the registry ────────────────────────────────────────────────────── */

static int check_registry(void)
{
    int failures = 0;
    static const char *const k_expect[] = {
        "runtime", "sync", "network", "storage",
        "wallet", "agents", "zcode", "metaverse",
    };
    const size_t n_expect = sizeof(k_expect) / sizeof(k_expect[0]);

    TR_CHECK("[render] the registry carries every frozen domain",
             telemetry_domain_count() == n_expect);

    int bad_order = 0, bad_roundtrip = 0, bad_shape = 0;
    for (size_t i = 0; i < telemetry_domain_count(); i++) {
        const struct telemetry_domain_schema *s = telemetry_domain_at(i);
        if (!s) { bad_shape++; continue; }
        if (i < n_expect && strcmp(s->domain, k_expect[i]) != 0)
            bad_order++;
        if (telemetry_domain_find(s->domain) != s)
            bad_roundtrip++;
        if (!s->schema_id || !s->schema_id[0] || !s->desc || !s->desc[0] ||
            s->group_count == 0 || s->leaf_count == 0 || s->snapshot_size == 0)
            bad_shape++;
    }
    TR_CHECK("[render] domains appear in telemetry_domains.def order",
             bad_order == 0);
    TR_CHECK("[render] every domain round-trips through telemetry_domain_find",
             bad_roundtrip == 0);
    TR_CHECK("[render] every schema carries an id, a description, groups, "
             "leaves and a snapshot size", bad_shape == 0);

    TR_CHECK("[render] an out-of-range index yields NULL, never a wild read",
             telemetry_domain_at(telemetry_domain_count()) == NULL &&
             telemetry_domain_at((size_t)-1) == NULL);
    TR_CHECK("[render] an unknown or empty domain name yields NULL",
             telemetry_domain_find("no_such_domain") == NULL &&
             telemetry_domain_find("") == NULL &&
             telemetry_domain_find(NULL) == NULL);
    return failures;
}

/* ── the descriptor tables ───────────────────────────────────────────── */

static size_t expect_width(enum telemetry_ctype c)
{
    switch (c) {
    case TLC_I64:  return sizeof(int64_t);
    case TLC_BOOL: return sizeof(bool);
    case TLC_TEXT: return (size_t)TELEMETRY_TEXT_MAX;
    }
    return 0;
}

static int check_offsets_and_paths(void)
{
    int failures = 0;
    int out_of_bounds = 0, bad_path = 0, no_group = 0, no_meaning = 0;
    char want[256];

    for (size_t d = 0; d < telemetry_domain_count(); d++) {
        const struct telemetry_domain_schema *s = telemetry_domain_at(d);
        for (size_t i = 0; i < s->leaf_count; i++) {
            const struct telemetry_leaf *lf = &s->leaves[i];
            size_t w = expect_width(lf->ctype);
            if (w == 0 || lf->value_off + w > s->snapshot_size ||
                lf->meta_off + sizeof(struct telemetry_leaf_meta) >
                    s->snapshot_size)
                out_of_bounds++;
            snprintf(want, sizeof want, "values.%s.%s", lf->group, lf->key);
            if (strcmp(lf->path, want) != 0)
                bad_path++;
            bool found = false;
            for (size_t g = 0; g < s->group_count && !found; g++)
                found = strcmp(s->groups[g].name, lf->group) == 0;
            if (!found)
                no_group++;
            /* The domain name IS the ontology subsystem name; without a row
             * the evaluator has no rule and the leaf can only report unknown. */
            if (!telemetry_field_lookup(s->domain, lf->path))
                no_meaning++;
        }
    }
    TR_CHECK("[render] every leaf offset lies inside its snapshot_size",
             out_of_bounds == 0);
    TR_CHECK("[render] every leaf path is values.<group>.<key>", bad_path == 0);
    TR_CHECK("[render] every leaf names a declared group", no_group == 0);
    TR_CHECK("[render] every leaf has a merged ontology row under its domain "
             "name", no_meaning == 0);
    return failures;
}

static int check_every_domain_renders(void)
{
    int failures = 0;
    int too_big = 0, render_failed = 0, missing_section = 0, missing_leaf = 0;

    for (size_t d = 0; d < telemetry_domain_count(); d++) {
        const struct telemetry_domain_schema *s = telemetry_domain_at(d);
        if (s->snapshot_size > sizeof g_scratch.bytes) { too_big++; continue; }
        memset(&g_scratch, 0, sizeof g_scratch);
        struct json_value out;
        json_init(&out);
        if (!telemetry_render(s, g_scratch.bytes, TLV_FULL, NULL, &out)) {
            render_failed++;
            json_free(&out);
            continue;
        }
        if (!json_get(&out, "values") || !json_get(&out, "leaves") ||
            !json_get(&out, "completeness") || !json_get(&out, "freshness") ||
            !json_get(&out, "health") || !json_get(&out, "_health"))
            missing_section++;
        /* Omission is impossible: every leaf's key is in the document even
         * though this snapshot was never filled in. */
        for (size_t i = 0; i < s->leaf_count; i++) {
            const struct telemetry_leaf *lf = &s->leaves[i];
            if (!dig3(&out, "values", lf->group, lf->key))
                missing_leaf++;
        }
        json_free(&out);
    }
    TR_CHECK("[render] the scratch buffer still fits every snapshot",
             too_big == 0);
    TR_CHECK("[render] every domain renders", render_failed == 0);
    TR_CHECK("[render] every reply carries values, leaves, completeness, "
             "freshness, health and the legacy _health tail",
             missing_section == 0);
    TR_CHECK("[render] a wholly unfilled snapshot still emits every leaf key",
             missing_leaf == 0);
    return failures;
}

/* ── a synthetic domain: tiers, and a refused table ──────────────────── */

/* This domain is declared here, above its first use, because the presence
 * tests below need a domain whose LEAF COUNT IS FIXED BY THIS FILE.
 *
 * Asserting an exact `completeness` count against a real domain looks fine
 * and rots on contact: these tests were written when `sync` had one leaf and
 * pinned `unset == 0`, and the moment a provider grew the domain to 44 the
 * assertions failed without anything being wrong. A fixture that must be
 * re-edited every time a provider gains a field is a fixture that will
 * eventually be re-edited to whatever makes it pass. So exact counts are
 * asserted here, and the real domains are asserted only on facts that hold at
 * any size.
 */
struct tr_fake_snapshot {
    int64_t a;
    struct telemetry_leaf_meta a_meta;
    int64_t b;
    struct telemetry_leaf_meta b_meta;
    int64_t c;
    struct telemetry_leaf_meta c_meta;
};

static const struct telemetry_group k_fake_groups[] = {
    { .name = "g", .desc = "one group, three tiers" },
};

static const struct telemetry_leaf k_fake_leaves[] = {
    { .group = "g", .key = "a", .path = "values.g.a",
      .value_off = offsetof(struct tr_fake_snapshot, a),
      .meta_off = offsetof(struct tr_fake_snapshot, a_meta),
      .ctype = TLC_I64, .unit = TFU_GAUGE, .tier = TLV_SUMMARY },
    { .group = "g", .key = "b", .path = "values.g.b",
      .value_off = offsetof(struct tr_fake_snapshot, b),
      .meta_off = offsetof(struct tr_fake_snapshot, b_meta),
      .ctype = TLC_I64, .unit = TFU_GAUGE, .tier = TLV_NORMAL },
    { .group = "g", .key = "c", .path = "values.g.c",
      .value_off = offsetof(struct tr_fake_snapshot, c),
      .meta_off = offsetof(struct tr_fake_snapshot, c_meta),
      .ctype = TLC_I64, .unit = TFU_GAUGE, .tier = TLV_FULL },
};

/* Deliberately NOT an ontology subsystem: every leaf therefore reports
 * unknown, which is precisely the contract stated on telemetry_domain_schema
 * and makes the per-view unknown_count a clean constant to compare. */
static const struct telemetry_domain_schema k_fake_schema = {
    .domain = "tr_fake_domain", .schema_id = "zcl.telemetry.tr_fake.v1",
    .desc = "synthetic three-tier domain used only by this test",
    .snapshot_size = sizeof(struct tr_fake_snapshot),
    .groups = k_fake_groups, .group_count = 1,
    .leaves = k_fake_leaves, .leaf_count = 3,
};

/* ── presence: unset, unavailable, present ───────────────────────────── */

static int check_unset_is_a_provider_defect(void)
{
    int failures = 0;
    /* Zero-initialized and never written: the state every provider starts in.
     * Asserted on the fixed-size synthetic domain so the exact counts and the
     * exact worst-path string stay meaningful as the real domains grow. */
    struct tr_fake_snapshot snap = {0};
    struct json_value out;
    json_init(&out);
    bool ok = telemetry_render(&k_fake_schema, &snap, TLV_FULL, NULL, &out);
    TR_CHECK("[render] an unfilled snapshot still renders", ok);

    const struct json_value *v = dig3(&out, "values", "g", "a");
    TR_CHECK("[render] the unset leaf's KEY is present and its value is null "
             "(never omitted, never a plausible 0)",
             v != NULL && v->type == JSON_NULL);
    TR_CHECK("[render] every unset leaf is counted as unset",
             json_get_int(dig2(&out, "completeness", "unset")) == 3 &&
             json_get_int(dig2(&out, "completeness", "present")) == 0);
    TR_CHECK("[render] unset raises provider_defect",
             json_get_bool(dig2(&out, "completeness", "provider_defect")));
    TR_CHECK("[render] unset is not 'complete'",
             !json_get_bool(dig2(&out, "completeness", "complete")));
    /* A leaf nobody wrote must not read as healthy, even though its row is
     * descriptive and carries no rule of its own. */
    const char *state = json_get_str(dig2(&out, "health", "state"));
    TR_CHECK("[render] unset drives the domain to at least unknown",
             state && strcmp(state, "unknown") == 0);
    TR_CHECK("[render] the legacy _health tail says not-ok",
             !json_get_bool(dig2(&out, "_health", "ok")));
    const char *reason = json_get_str(dig2(&out, "_health", "reason"));
    TR_CHECK("[render] _health.reason is the mechanical triple "
             "<domain>:<state>:<worst_path>",
             reason != NULL &&
             strcmp(reason, "tr_fake_domain:unknown:values.g.a") == 0);
    json_free(&out);

    /* The same contract on a real domain, at whatever size it currently is:
     * no exact counts, so this keeps testing the thing rather than the size. */
    struct runtime_snapshot real = {0};
    struct json_value rout;
    json_init(&rout);
    bool rok = telemetry_render(&g_runtime_schema, &real, TLV_FULL, NULL, &rout);
    TR_CHECK("[render] a real domain's unfilled snapshot renders too", rok);
    TR_CHECK("[render] a real provider that wrote nothing is a provider defect",
             json_get_bool(dig2(&rout, "completeness", "provider_defect")) &&
             json_get_int(dig2(&rout, "completeness", "present")) == 0 &&
             !json_get_bool(dig2(&rout, "completeness", "complete")));
    const char *rstate = json_get_str(dig2(&rout, "health", "state"));
    TR_CHECK("[render] and it reads unknown, never ok",
             rstate && strcmp(rstate, "unknown") == 0);
    json_free(&rout);
    return failures;
}

static int check_unavailable_is_not_unhealthy(void)
{
    int failures = 0;

    /* Baseline the domain at its current size rather than hardcoding it, then
     * assert the DIFFERENCE. Marking one leaf unavailable must move it out of
     * the unset bucket, not add a second count of it. */
    struct sync_snapshot base = {0};
    struct json_value b;
    json_init(&b);
    bool bok = telemetry_render(&g_sync_schema, &base, TLV_FULL, NULL, &b);
    TR_CHECK("[render] the all-unset baseline renders", bok);
    int64_t unset_all = json_get_int(dig2(&b, "completeness", "unset"));
    json_free(&b);
    TR_CHECK("[render] the baseline has an unset leaf available to move",
             unset_all >= 1);

    struct sync_snapshot snap = {0};
    TELEMETRY_UNAVAILABLE_LEAF(&snap, collected_unix, "progress_store_busy");

    struct json_value out;
    json_init(&out);
    bool ok = telemetry_render(&g_sync_schema, &snap, TLV_FULL, NULL, &out);
    TR_CHECK("[render] an unavailable leaf renders", ok);

    const struct json_value *v = dig3(&out, "values", "meta", "collected_unix");
    TR_CHECK("[render] an unavailable leaf renders its key as null",
             v != NULL && v->type == JSON_NULL);
    TR_CHECK("[render] it is counted as unavailable, and leaves the unset "
             "bucket rather than being counted twice",
             json_get_int(dig2(&out, "completeness", "unavailable")) == 1 &&
             json_get_int(dig2(&out, "completeness", "unset")) == unset_all - 1);

    const struct json_value *lm =
        dig2(&out, "leaves", "values.meta.collected_unix");
    const char *why = json_get_str(json_get(lm, "reason"));
    TR_CHECK("[render] the provenance entry carries the static reason token",
             why != NULL && strcmp(why, "progress_store_busy") == 0);
    const char *pres = json_get_str(json_get(lm, "presence"));
    TR_CHECK("[render] the provenance entry names the presence",
             pres != NULL && strcmp(pres, "unavailable") == 0);
    TR_CHECK("[render] an unavailable age renders as null, not as 0",
             json_get(lm, "age_ms") != NULL &&
             json_get(lm, "age_ms")->type == JSON_NULL);

    /* A descriptive leaf we could not read is not a health problem — and it is
     * emphatically not 'unhealthy'. */
    const char *state = json_get_str(dig2(&out, "health", "state"));
    TR_CHECK("[render] an unreadable descriptive leaf is not reported broken",
             state && strcmp(state, "unhealthy") != 0 &&
             json_get_int(dig2(&out, "health", "unhealthy_count")) == 0);
    json_free(&out);
    return failures;
}

/* `provider_defect` must answer "did a provider forget a leaf", not merely
 * "is this snapshot incomplete". Telling those apart needs every leaf in the
 * domain accounted for — which is only cheap on the synthetic domain, since a
 * real one would mean filling dozens of fields by hand. */
static int check_unavailable_alone_is_not_a_provider_defect(void)
{
    int failures = 0;
    struct tr_fake_snapshot snap = {0};
    TELEMETRY_SET_I64(&snap, a, 1, TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&snap, b, 2, TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_UNAVAILABLE_LEAF(&snap, c, "deliberately_unreadable");

    struct json_value out;
    json_init(&out);
    bool ok = telemetry_render(&k_fake_schema, &snap, TLV_FULL, NULL, &out);
    TR_CHECK("[render] a fully accounted-for snapshot renders", ok);
    TR_CHECK("[render] every leaf is accounted for: nothing left unset",
             json_get_int(dig2(&out, "completeness", "unset")) == 0 &&
             json_get_int(dig2(&out, "completeness", "present")) == 2 &&
             json_get_int(dig2(&out, "completeness", "unavailable")) == 1);
    TR_CHECK("[render] a real 'could not read it' is NOT a provider defect",
             !json_get_bool(dig2(&out, "completeness", "provider_defect")));
    /* Still not complete — the reader is owed the distinction between "all
     * present" and "all accounted for". */
    TR_CHECK("[render] but it is still not 'complete'",
             !json_get_bool(dig2(&out, "completeness", "complete")));
    json_free(&out);
    return failures;
}

/* ── fitting a document to a reply frame ─────────────────────────────── */

/* Measured, not guessed: how big the synthetic domain actually renders at a
 * given view right now. Hardcoding these would reintroduce exactly the
 * size-coupling this file just removed. */
static size_t tr_size_at(enum telemetry_view v, int *failed)
{
    struct tr_fake_snapshot snap = {0};
    TELEMETRY_SET_I64(&snap, a, 1, TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&snap, b, 2, TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&snap, c, 3, TELEMETRY_SRC_IN_PROCESS);
    struct json_value out;
    json_init(&out);
    if (!telemetry_render(&k_fake_schema, &snap, v, NULL, &out)) {
        (*failed)++;
        json_free(&out);
        return 0;
    }
    size_t n = json_write(&out, NULL, 0);
    json_free(&out);
    return n;
}

static int check_reply_fitting_steps_down(void)
{
    int failures = 0;
    int failed = 0;
    size_t full_sz = tr_size_at(TLV_FULL, &failed);
    size_t summary_sz = tr_size_at(TLV_SUMMARY, &failed);
    TR_CHECK("[reply] the probe rendered both tiers", failed == 0);
    TR_CHECK("[reply] full is larger than summary, so there is a step to take",
             full_sz > summary_sz);

    struct tr_fake_snapshot snap = {0};
    TELEMETRY_SET_I64(&snap, a, 1, TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&snap, b, 2, TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&snap, c, 3, TELEMETRY_SRC_IN_PROCESS);

    /* Roomy frame: no downgrade, and it does not render twice to find out. */
    struct json_value d1;
    json_init(&d1);
    struct telemetry_reply_fit f1;
    bool r1 = telemetry_reply_render_fitting(&k_fake_schema, &snap, TLV_FULL,
                                             full_sz + 1024, &d1, &f1);
    TR_CHECK("[reply] a document that fits is shipped at the view asked for",
             r1 && f1.rendered && f1.fits && f1.view == TLV_FULL &&
             f1.attempts == 1 && f1.bytes == full_sz);
    json_free(&d1);

    /* Frame between the two tiers: it must step down rather than overflow. */
    struct json_value d2;
    json_init(&d2);
    struct telemetry_reply_fit f2;
    bool r2 = telemetry_reply_render_fitting(&k_fake_schema, &snap, TLV_FULL,
                                             summary_sz, &d2, &f2);
    TR_CHECK("[reply] a document that does not fit steps down to one that does",
             r2 && f2.rendered && f2.fits && f2.view == TLV_SUMMARY &&
             f2.bytes <= summary_sz && f2.attempts > 1);
    json_free(&d2);

    /* The case the per-controller copies got wrong: nothing fits at all. The
     * old code returned the summary view and reported success, so the caller
     * shipped an oversized document and the registry turned it into an EMPTY
     * reply — indistinguishable from "the subsystem had nothing to say". */
    struct json_value d3;
    json_init(&d3);
    struct telemetry_reply_fit f3;
    bool r3 = telemetry_reply_render_fitting(&k_fake_schema, &snap, TLV_FULL,
                                             0, &d3, &f3);
    TR_CHECK("[reply] when even the smallest view overflows, the measurement "
             "succeeds and says so rather than claiming a fit",
             r3 && f3.rendered && !f3.fits);
    TR_CHECK("[reply] and it reports the real size, which is the only thing "
             "that makes the failure actionable",
             f3.bytes > 0 && f3.bytes == summary_sz);
    TR_CHECK("[reply] having tried every tier on the way down",
             f3.attempts == 3 && f3.view == TLV_SUMMARY);
    json_free(&d3);

    /* Starting at summary must not climb back up to full. */
    struct json_value d4;
    json_init(&d4);
    struct telemetry_reply_fit f4;
    (void)telemetry_reply_render_fitting(&k_fake_schema, &snap, TLV_SUMMARY, 0,
                                         &d4, &f4);
    TR_CHECK("[reply] a requested summary starts at summary, never above it",
             f4.attempts == 1 && f4.view == TLV_SUMMARY);
    json_free(&d4);
    return failures;
}

/* Mark every leaf of `s` present in `snap`, writing through the descriptor
 * table rather than naming members. Used by the checks below so they assert
 * "all of them" instead of a leaf count that a domain lane can change under
 * them — an earlier form of check_present_renders_the_value filled one wallet
 * leaf and asserted present == 1, and silently stopped testing completeness
 * the day the wallet domain grew a second field. */
static void fill_every_leaf(const struct telemetry_domain_schema *s, void *snap,
                            int64_t value)
{
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        struct telemetry_leaf_meta *m =
            (struct telemetry_leaf_meta *)((unsigned char *)snap +
                                           lf->meta_off);
        unsigned char *v = (unsigned char *)snap + lf->value_off;
        switch (lf->ctype) {
        case TLC_I64: {
            int64_t tmp = value;
            memcpy(v, &tmp, sizeof tmp);
            break;
        }
        case TLC_BOOL: {
            bool tmp = true;
            memcpy(v, &tmp, sizeof tmp);
            break;
        }
        default:
            /* Text and anything added later: presence is what these checks
             * are about, and an empty string is a legitimate present value. */
            break;
        }
        m->presence = TELEMETRY_PRESENT;
        m->source = TELEMETRY_SRC_IN_PROCESS;
        m->observed_unix = value;
        m->age_ms = 0;
        m->reason = NULL;
    }
}

static int check_present_renders_the_value(void)
{
    int failures = 0;
    struct wallet_snapshot snap = {0};
    fill_every_leaf(&g_wallet_schema, &snap, 1750000000);

    struct json_value out;
    json_init(&out);
    bool ok = telemetry_render(&g_wallet_schema, &snap, TLV_FULL, NULL, &out);
    TR_CHECK("[render] a filled snapshot renders", ok);
    TR_CHECK("[render] the value survives the round trip",
             json_get_int(dig3(&out, "values", "meta", "collected_unix")) ==
             1750000000);
    /* Compared against the schema's own leaf count, so this stays a real
     * assertion whatever size the domain grows to. */
    TR_CHECK("[render] a fully-filled snapshot is complete and defect-free",
             json_get_bool(dig2(&out, "completeness", "complete")) &&
             !json_get_bool(dig2(&out, "completeness", "provider_defect")) &&
             json_get_int(dig2(&out, "completeness", "present")) ==
                 (int64_t)g_wallet_schema.leaf_count);
    TR_CHECK("[render] FULL reports provenance for a present leaf too",
             dig2(&out, "leaves", "values.meta.collected_unix") != NULL);
    const struct json_value *src =
        json_get(dig2(&out, "leaves", "values.meta.collected_unix"), "source");
    TR_CHECK("[render] provenance names where the value came from",
             json_get_str(src) && strcmp(json_get_str(src), "in_process") == 0);
    json_free(&out);

    /* Below FULL the provenance block reports only the leaves whose presence
     * changes how the value must be read. */
    json_init(&out);
    ok = telemetry_render(&g_wallet_schema, &snap, TLV_NORMAL, NULL, &out);
    TR_CHECK("[render] NORMAL omits provenance for a plainly-present leaf",
             ok && dig2(&out, "leaves", "values.meta.collected_unix") == NULL &&
             json_get(&out, "leaves") != NULL);
    json_free(&out);

    /* A fully-present snapshot must never be judged UNKNOWN for completeness
     * reasons, in ANY domain. This is the property the single-domain check
     * above used to stand in for; asserted across the registry it cannot go
     * stale when one domain grows. A domain may still be degraded or unhealthy
     * on the VALUES — that is the evaluator doing its job — but "we could not
     * read it" must be gone. */
    size_t unknown_though_filled = 0, defect_though_filled = 0;
    for (size_t d = 0; d < telemetry_domain_count(); d++) {
        const struct telemetry_domain_schema *s = telemetry_domain_at(d);
        if (s->snapshot_size > sizeof g_scratch.bytes)
            continue;
        memset(&g_scratch, 0, sizeof g_scratch);
        fill_every_leaf(s, g_scratch.bytes, 1750000000);
        struct json_value dv;
        json_init(&dv);
        if (telemetry_render(s, g_scratch.bytes, TLV_FULL, NULL, &dv)) {
            if (json_get_bool(dig2(&dv, "completeness", "provider_defect")))
                defect_though_filled++;
            const char *st = json_get_str(dig2(&dv, "health", "state"));
            /* tr_fake-style domains with no ontology rows legitimately report
             * unknown; a registered domain has rules, so unknown after a full
             * fill means a leaf the evaluator could not read. */
            if (st && strcmp(st, "unknown") == 0 &&
                json_get_int(dig2(&dv, "completeness", "unset")) > 0)
                unknown_though_filled++;
        }
        json_free(&dv);
    }
    TR_CHECK("[render] a fully-filled snapshot reports no provider defect, in "
             "any registered domain", defect_though_filled == 0);
    TR_CHECK("[render] no registered domain is still counting unset leaves "
             "after every leaf was filled", unknown_though_filled == 0);
    return failures;
}

/* ── the fix: unreadable is UNKNOWN, never UNHEALTHY ─────────────────── */

static enum telemetry_verdict eval_against(const struct telemetry_field *f,
                                           const char *raw)
{
    struct json_value dump;
    json_init(&dump);
    if (!json_read(&dump, raw, strlen(raw))) {
        json_free(&dump);
        return TV_NOT_EVALUATED;
    }
    const struct json_value *v = NULL;
    enum telemetry_verdict verdict = telemetry_field_evaluate(f, &dump, &v);
    json_free(&dump);
    return verdict;
}

static int check_bool_rule_type_mismatch(void)
{
    int failures = 0;
    /* A critical expect-true row: exactly the shape whose old behaviour turned
     * one unreadable flag into a whole-domain critical. */
    const struct telemetry_field want_true = {
        .subsystem = "unit_test", .path = "flag", .unit = TFU_BOOL,
        .rule = TFR_EXPECT_TRUE, .operand = NULL, .threshold = 0,
        .severity = TFS_CRITICAL, .means = "m", .implies = "i", .next = "n",
    };
    const struct telemetry_field want_false = {
        .subsystem = "unit_test", .path = "flag", .unit = TFU_BOOL,
        .rule = TFR_EXPECT_FALSE, .operand = NULL, .threshold = 0,
        .severity = TFS_CRITICAL, .means = "m", .implies = "i", .next = "n",
    };

    TR_CHECK("[render] expect_true still judges a real true",
             eval_against(&want_true, "{\"flag\":true}") == TV_HEALTHY);
    TR_CHECK("[render] expect_true still judges a real false",
             eval_against(&want_true, "{\"flag\":false}") == TV_UNHEALTHY);
    /* THE FIX. A null is the render layer's representation of a leaf that
     * could not be read; it is not a bool, so it is absent, not broken. */
    TR_CHECK("[render] expect_true on a JSON null is ABSENT, not unhealthy",
             eval_against(&want_true, "{\"flag\":null}") == TV_ABSENT);
    TR_CHECK("[render] expect_true on a non-bool type is ABSENT, not unhealthy",
             eval_against(&want_true, "{\"flag\":\"yes\"}") == TV_ABSENT);
    TR_CHECK("[render] expect_false still judges real bools",
             eval_against(&want_false, "{\"flag\":false}") == TV_HEALTHY &&
             eval_against(&want_false, "{\"flag\":true}") == TV_UNHEALTHY);
    TR_CHECK("[render] expect_false on a JSON null is ABSENT, not unhealthy",
             eval_against(&want_false, "{\"flag\":null}") == TV_ABSENT);
    TR_CHECK("[render] a missing key stays absent",
             eval_against(&want_true, "{\"other\":true}") == TV_ABSENT);

    TR_CHECK("[render] a NULL row or dump is not evaluated rather than judged",
             telemetry_field_evaluate(NULL, NULL, NULL) == TV_NOT_EVALUATED);

    /* The wire spellings are what dumpstate has always emitted. */
    TR_CHECK("[render] verdict names are the historical strings",
             strcmp(telemetry_verdict_name(TV_HEALTHY), "healthy") == 0 &&
             strcmp(telemetry_verdict_name(TV_UNHEALTHY), "unhealthy") == 0 &&
             strcmp(telemetry_verdict_name(TV_NOT_JUDGED), "not_judged") == 0 &&
             strcmp(telemetry_verdict_name(TV_ABSENT), "absent") == 0 &&
             strcmp(telemetry_verdict_name(TV_NOT_EVALUATED),
                    "not_evaluated") == 0);
    return failures;
}

static size_t rendered_at(const struct telemetry_domain_schema *s,
                          const void *snap, enum telemetry_view view,
                          int64_t *out_unknown, int *failed)
{
    struct json_value out;
    json_init(&out);
    if (!telemetry_render(s, snap, view, NULL, &out)) {
        (*failed)++;
        json_free(&out);
        return 0;
    }
    size_t n = (size_t)json_get_int(dig2(&out, "completeness",
                                         "leaves_rendered"));
    *out_unknown = json_get_int(dig2(&out, "health", "unknown_count"));
    json_free(&out);
    return n;
}

static int check_view_prunes_output_not_judgement(void)
{
    int failures = 0;
    struct tr_fake_snapshot snap = {0};
    TELEMETRY_SET_I64(&snap, a, 1, TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&snap, b, 2, TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&snap, c, 3, TELEMETRY_SRC_IN_PROCESS);

    int failed = 0;
    int64_t u_sum = -1, u_norm = -1, u_full = -1;
    size_t n_sum = rendered_at(&k_fake_schema, &snap, TLV_SUMMARY, &u_sum,
                               &failed);
    size_t n_norm = rendered_at(&k_fake_schema, &snap, TLV_NORMAL, &u_norm,
                                &failed);
    size_t n_full = rendered_at(&k_fake_schema, &snap, TLV_FULL, &u_full,
                                &failed);

    TR_CHECK("[render] all three views render", failed == 0);
    TR_CHECK("[render] a tier is the SHALLOWEST view that shows a field",
             n_sum == 1 && n_norm == 2 && n_full == 3);
    /* The whole point: judgement does not shrink with the view. */
    TR_CHECK("[render] every leaf is judged at every view, so summary cannot "
             "report ok over a full-tier problem",
             u_sum == 3 && u_norm == 3 && u_full == 3);

    /* A domain with no ontology rows can only report unknown — never ok. */
    struct json_value out;
    json_init(&out);
    bool ok = telemetry_render(&k_fake_schema, &snap, TLV_SUMMARY, NULL, &out);
    const char *state = json_get_str(dig2(&out, "health", "state"));
    TR_CHECK("[render] a domain whose name is not an ontology subsystem "
             "reports unknown rather than health",
             ok && state && strcmp(state, "unknown") == 0 &&
             !json_get_bool(dig2(&out, "_health", "ok")));
    TR_CHECK("[render] the summary view still emits a leaf it cannot judge",
             dig3(&out, "values", "g", "a") != NULL &&
             dig3(&out, "values", "g", "c") == NULL);
    json_free(&out);
    return failures;
}

static int check_out_of_bounds_table_is_refused(void)
{
    int failures = 0;
    struct tr_fake_snapshot snap = {0};

    /* value_off one byte past the end of the declared snapshot. */
    struct telemetry_leaf bad_leaf = k_fake_leaves[0];
    bad_leaf.value_off = sizeof(struct tr_fake_snapshot) - 1;
    struct telemetry_domain_schema bad = k_fake_schema;
    bad.leaves = &bad_leaf;
    bad.leaf_count = 1;

    struct json_value out;
    json_init(&out);
    TR_CHECK("[render] a descriptor that would read past snapshot_size is "
             "REFUSED, not read",
             !telemetry_render(&bad, &snap, TLV_FULL, NULL, &out));
    json_free(&out);

    struct telemetry_domain_verdict v;
    TR_CHECK("[render] telemetry_evaluate refuses the same table",
             !telemetry_evaluate(&bad, &snap, &v));

    /* A meta offset past the end is refused on the same proof. */
    struct telemetry_leaf bad_meta = k_fake_leaves[0];
    bad_meta.meta_off = sizeof(struct tr_fake_snapshot);
    bad.leaves = &bad_meta;
    json_init(&out);
    TR_CHECK("[render] an out-of-bounds meta offset is refused too",
             !telemetry_render(&bad, &snap, TLV_FULL, NULL, &out));
    json_free(&out);

    TR_CHECK("[render] NULL arguments are refused rather than dereferenced",
             !telemetry_render(NULL, &snap, TLV_FULL, NULL, &out) &&
             !telemetry_render(&k_fake_schema, NULL, TLV_FULL, NULL, &out) &&
             !telemetry_render(&k_fake_schema, &snap, TLV_FULL, NULL, NULL) &&
             !telemetry_evaluate(&k_fake_schema, &snap, NULL));
    json_free(&out);
    return failures;
}

/* ── the document is complete, or it is a failure ────────────────────── */

/* The json layer has no injectable allocation failure, so the OOM branch is
 * unreachable from a test. What IS reachable — and what actually regresses —
 * is a refactor that drops a section, so this walks every domain at every view
 * and asserts the full promised shape: a lost `health`, or a lost key inside
 * `completeness`, fails loudly instead of returning a short document that
 * reads like a healthy one. telemetry_render() enforces the same list
 * internally (document_is_complete) before it returns true. */
static int check_document_shape_is_complete(void)
{
    int failures = 0;
    static const char *const k_top[] = {
        "schema", "domain", "view", "values", "leaves",
        "completeness", "freshness", "health", "_health",
    };
    static const char *const k_completeness[] = {
        "leaves_total", "leaves_rendered", "present", "unavailable",
        "not_applicable", "truncated", "unset", "complete", "provider_defect",
    };
    static const char *const k_freshness[] = {
        "oldest_observed_unix", "max_age_ms", "leaves_with_unknown_age",
        "any_unknown_age",
    };
    static const char *const k_health[] = {
        "state", "rules_evaluated", "unhealthy_count", "unknown_count",
        "unhealthy", "findings_truncated",
    };
    static const enum telemetry_view k_views[] = {
        TLV_SUMMARY, TLV_NORMAL, TLV_FULL,
    };
    int missing_top = 0, missing_sub = 0, not_rendered = 0;

    for (size_t d = 0; d < telemetry_domain_count(); d++) {
        const struct telemetry_domain_schema *s = telemetry_domain_at(d);
        if (s->snapshot_size > sizeof g_scratch.bytes) { not_rendered++; continue; }
        for (size_t vi = 0; vi < sizeof k_views / sizeof k_views[0]; vi++) {
            memset(&g_scratch, 0, sizeof g_scratch);
            struct json_value out;
            json_init(&out);
            if (!telemetry_render(s, g_scratch.bytes, k_views[vi], NULL, &out)) {
                not_rendered++;
                json_free(&out);
                continue;
            }
            for (size_t i = 0; i < sizeof k_top / sizeof k_top[0]; i++)
                if (!json_get(&out, k_top[i]))
                    missing_top++;
            for (size_t i = 0; i < sizeof k_completeness / sizeof k_completeness[0]; i++)
                if (!dig2(&out, "completeness", k_completeness[i]))
                    missing_sub++;
            for (size_t i = 0; i < sizeof k_freshness / sizeof k_freshness[0]; i++)
                if (!dig2(&out, "freshness", k_freshness[i]))
                    missing_sub++;
            for (size_t i = 0; i < sizeof k_health / sizeof k_health[0]; i++)
                if (!dig2(&out, "health", k_health[i]))
                    missing_sub++;
            /* health.unhealthy is the one whose absence would read as
             * "nothing is wrong", so it must be a real ARRAY, not merely a
             * present key. */
            const struct json_value *uh = dig2(&out, "health", "unhealthy");
            if (!uh || uh->type != JSON_ARR)
                missing_sub++;
            if (!dig2(&out, "_health", "ok") ||
                !dig2(&out, "_health", "reason"))
                missing_sub++;
            json_free(&out);
        }
    }
    TR_CHECK("[render] every domain renders at every view", not_rendered == 0);
    TR_CHECK("[render] a successful reply always carries all nine top-level "
             "sections — a partial document is a failure, never a success",
             missing_top == 0);
    TR_CHECK("[render] every key inside completeness, freshness, health and "
             "_health is present in every successful reply", missing_sub == 0);
    return failures;
}

/* ── views, groups and text ──────────────────────────────────────────── */

static int check_view_parse(void)
{
    int failures = 0;
    const char *group = (const char *)1;
    bool unknown = true;

    TR_CHECK("[render] no key means the normal view",
             telemetry_view_parse(NULL, &group, &unknown) == TLV_NORMAL &&
             group == NULL && !unknown);
    TR_CHECK("[render] an empty key means the normal view",
             telemetry_view_parse("", &group, &unknown) == TLV_NORMAL &&
             group == NULL && !unknown);
    TR_CHECK("[render] the three view names parse",
             telemetry_view_parse("summary", &group, &unknown) == TLV_SUMMARY &&
             telemetry_view_parse("normal", &group, &unknown) == TLV_NORMAL &&
             telemetry_view_parse("full", &group, &unknown) == TLV_FULL);
    TR_CHECK("[render] a group name selects that group at full detail",
             telemetry_view_parse("meta", &group, &unknown) == TLV_FULL &&
             group != NULL && strcmp(group, "meta") == 0 && !unknown);
    TR_CHECK("[render] a key that is neither view nor group shape falls back "
             "to normal and SAYS it was unrecognized",
             telemetry_view_parse("Not A Group!", &group, &unknown) ==
             TLV_NORMAL && group == NULL && unknown);
    TR_CHECK("[render] the view names round-trip",
             strcmp(telemetry_view_name(TLV_SUMMARY), "summary") == 0 &&
             strcmp(telemetry_view_name(TLV_NORMAL), "normal") == 0 &&
             strcmp(telemetry_view_name(TLV_FULL), "full") == 0);
    return failures;
}

static int check_group_filter(void)
{
    int failures = 0;
    struct storage_snapshot snap = {0};
    TELEMETRY_SET_I64(&snap, collected_unix, 42, TELEMETRY_SRC_DERIVED);

    struct json_value out;
    json_init(&out);
    bool ok = telemetry_render(&g_storage_schema, &snap, TLV_FULL, "meta",
                               &out);
    TR_CHECK("[render] a real group filter matches and renders that group",
             ok && json_get_bool(json_get(&out, "group_filter_matched")) &&
             dig3(&out, "values", "meta", "collected_unix") != NULL);
    json_free(&out);

    json_init(&out);
    ok = telemetry_render(&g_storage_schema, &snap, TLV_FULL, "no_such_group",
                          &out);
    TR_CHECK("[render] a filter naming no group renders nothing and SAYS so, "
             "rather than reading like an empty domain",
             ok && !json_get_bool(json_get(&out, "group_filter_matched")) &&
             json_size(json_get(&out, "values")) == 0 &&
             json_get_int(dig2(&out, "completeness", "leaves_rendered")) == 0);
    /* Judgement is unaffected by the filter — the domain is still whole. */
    TR_CHECK("[render] a group filter does not shrink the judged set",
             json_get_int(dig2(&out, "completeness", "leaves_total")) ==
             (int64_t)g_storage_schema.leaf_count);
    json_free(&out);
    return failures;
}

static int check_text_setter(void)
{
    int failures = 0;
    struct telemetry_leaf_meta meta = {0};
    char buf[8];

    telemetry_set_text_impl(buf, sizeof buf, &meta, "short",
                            TELEMETRY_SRC_CONFIG);
    TR_CHECK("[render] a fitting string is present and copied",
             strcmp(buf, "short") == 0 &&
             meta.presence == TELEMETRY_PRESENT &&
             meta.source == TELEMETRY_SRC_CONFIG);

    telemetry_set_text_impl(buf, sizeof buf, &meta, "far too long to fit",
                            TELEMETRY_SRC_CONFIG);
    TR_CHECK("[render] an over-long string truncates LOUDLY, never silently",
             strlen(buf) == sizeof(buf) - 1 &&
             meta.presence == TELEMETRY_TRUNCATED &&
             meta.reason && strcmp(meta.reason, "text_too_long") == 0);

    telemetry_set_text_impl(buf, sizeof buf, &meta, NULL,
                            TELEMETRY_SRC_CONFIG);
    TR_CHECK("[render] a NULL string is a failed read, not an empty value",
             buf[0] == '\0' && meta.presence == TELEMETRY_UNAVAILABLE &&
             meta.reason && strcmp(meta.reason, "text_value_null") == 0);

    TR_CHECK("[render] the presence and source names are stable",
             strcmp(telemetry_presence_name(TELEMETRY_UNSET), "unset") == 0 &&
             strcmp(telemetry_presence_name(TELEMETRY_NOT_APPLICABLE),
                    "not_applicable") == 0 &&
             strcmp(telemetry_source_name(TELEMETRY_SRC_CACHED_PUBLICATION),
                    "cached_publication") == 0 &&
             strcmp(telemetry_health_name(TELEMETRY_HEALTH_DEGRADED),
                    "degraded") == 0);
    return failures;
}

/* A truncated string renders from its surviving bytes, which is more use than
 * a null — but only if the reader can still SEE that bytes were dropped. The
 * presence must travel with the value at every tier, not just at full, or a
 * summary reply shows a shortened string as if it were whole. */
struct tr_text_snapshot {
    char label[TELEMETRY_TEXT_MAX];
    struct telemetry_leaf_meta label_meta;
};

static const struct telemetry_group k_text_groups[] = {
    { .name = "g", .desc = "one text leaf, visible at every tier" },
};

static const struct telemetry_leaf k_text_leaves[] = {
    { .group = "g", .key = "label", .path = "values.g.label",
      .value_off = offsetof(struct tr_text_snapshot, label),
      .meta_off = offsetof(struct tr_text_snapshot, label_meta),
      .ctype = TLC_TEXT, .unit = TFU_IDENTITY, .tier = TLV_SUMMARY },
};

static const struct telemetry_domain_schema k_text_schema = {
    .domain = "tr_text_domain", .schema_id = "zcl.telemetry.tr_text.v1",
    .desc = "synthetic text domain used only by this test",
    .snapshot_size = sizeof(struct tr_text_snapshot),
    .groups = k_text_groups, .group_count = 1,
    .leaves = k_text_leaves, .leaf_count = 1,
};

static int check_truncation_is_visible_at_every_tier(void)
{
    int failures = 0;
    struct tr_text_snapshot snap = {0};
    char too_long[TELEMETRY_TEXT_MAX + 16];
    memset(too_long, 'x', sizeof too_long - 1);
    too_long[sizeof too_long - 1] = '\0';
    TELEMETRY_SET_TEXT(&snap, label, too_long, TELEMETRY_SRC_CONFIG);

    static const enum telemetry_view k_views[] = {
        TLV_SUMMARY, TLV_NORMAL, TLV_FULL,
    };
    int no_value = 0, no_signal = 0, not_counted = 0;
    for (size_t i = 0; i < sizeof k_views / sizeof k_views[0]; i++) {
        struct json_value out;
        json_init(&out);
        if (!telemetry_render(&k_text_schema, &snap, k_views[i], NULL, &out)) {
            no_value++;
            json_free(&out);
            continue;
        }
        const char *v = json_get_str(dig3(&out, "values", "g", "label"));
        if (!v || strlen(v) != TELEMETRY_TEXT_MAX - 1)
            no_value++;
        const char *pres =
            json_get_str(json_get(dig2(&out, "leaves", "values.g.label"),
                                  "presence"));
        if (!pres || strcmp(pres, "truncated") != 0)
            no_signal++;
        if (json_get_int(dig2(&out, "completeness", "truncated")) != 1 ||
            json_get_bool(dig2(&out, "completeness", "complete")))
            not_counted++;
        json_free(&out);
    }
    TR_CHECK("[render] a truncated leaf still renders its surviving bytes",
             no_value == 0);
    TR_CHECK("[render] the truncated presence travels with the value at EVERY "
             "view tier, so a summary can never show a shortened string as if "
             "it were whole", no_signal == 0);
    TR_CHECK("[render] truncation is counted and breaks completeness",
             not_counted == 0);
    return failures;
}

int test_telemetry_render(void)
{
    int failures = 0;
    failures += check_registry();
    failures += check_offsets_and_paths();
    failures += check_every_domain_renders();
    failures += check_unset_is_a_provider_defect();
    failures += check_unavailable_is_not_unhealthy();
    failures += check_unavailable_alone_is_not_a_provider_defect();
    failures += check_reply_fitting_steps_down();
    failures += check_present_renders_the_value();
    failures += check_bool_rule_type_mismatch();
    failures += check_view_prunes_output_not_judgement();
    failures += check_document_shape_is_complete();
    failures += check_truncation_is_visible_at_every_tier();
    failures += check_out_of_bounds_table_is_refused();
    failures += check_view_parse();
    failures += check_group_filter();
    failures += check_text_setter();
    printf("=== telemetry_render: %d failures ===\n", failures);
    return failures;
}
