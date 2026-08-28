/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Group `mesh_observation_dump` — the OPERATOR-FACING renderer,
 * app/controllers/src/diagnostics_mesh_observation.c.
 *
 * The two groups either side of this one already defend the emitter
 * (`mesh_observation`) and the fold (`mesh_observation_compose`). Nothing
 * defended the thing an operator actually reads. That gap had a structural
 * cause and not merely an absence of effort: the coverage list rendered
 * straight out of one file-static slot array, so no test could hand it an
 * input. The fix follows the precedent of
 * agent_push_security_posture_snapshot_json — a pure render seam that takes
 * the already-collected data as an argument — and this group drives that
 * seam.
 *
 * WHAT THIS GROUP DEFENDS.
 *
 *   1. Coverage is REPORTED, not implied. Zero collected records renders an
 *      EMPTY `records` array, never a missing key. A reader must be able to
 *      tell "I looked and found nobody" from "this build does not say".
 *   2. Every slot appears, in order, one object each, whatever its outcome.
 *      A slot that was never probed is not omitted — omitting it would turn
 *      "I did not look" into silence.
 *   3. Elapsed is published beside the budget on EVERY outcome, so a spent
 *      budget and a refusal are never byte-identical rows. That is the
 *      file's own stated invariant.
 *   4. A machine's PLATFORM is readable beside its onion. `os`/`arch` are
 *      carried verbatim, including a token this build has never heard of,
 *      because refusing an unknown platform would drop the first node of
 *      every new one.
 *   5. AND, the honest half of 4: an emitter that said NOTHING renders as
 *      having said nothing. Not this reader's own build target, not
 *      "linux", not "unknown". Every check below carries that fail-arm,
 *      because a defaulted platform is exactly the confident-about-nothing
 *      failure this surface exists to refuse.
 *   6. The live dumpers themselves, with no sample and no chain, report
 *      UNVERIFIED with their coverage counts, never empty-but-healthy.
 */

#include "test/test_core.h"

#include "controllers/observation_site_controller.h"
#include "services/mesh_observation.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>

/* ── fixtures ─────────────────────────────────────────────────────────── */

static void dump_slot_init(struct mesh_obs_slot *s, const char *onion,
                           enum mesh_obs_outcome fetch)
{
    memset(s, 0, sizeof(*s));
    snprintf(s->onion, sizeof(s->onion), "%s", onion);
    s->fetch = fetch;
}

static void dump_slot_platform(struct mesh_obs_slot *s, const char *os,
                               const char *arch)
{
    snprintf(s->rec.self.os, sizeof(s->rec.self.os), "%s", os);
    snprintf(s->rec.self.arch, sizeof(s->rec.self.arch), "%s", arch);
}

/* The rendered `records` array, or NULL. Fails loud rather than returning a
 * plausible empty: a helper that quietly answered "no records" would make
 * every check below vacuous. */
static const struct json_value *dump_records(const struct json_value *out)
{
    const struct json_value *r = json_get(out, "records");
    if (!r || r->type != JSON_ARR)
        return NULL;   /* raw-return-ok:caller-asserts-non-null */
    return r;
}

static const struct json_value *dump_row(const struct json_value *out,
                                         size_t i)
{
    const struct json_value *r = dump_records(out);
    if (!r || i >= json_size(r))
        return NULL;   /* raw-return-ok:caller-asserts-non-null */
    return json_at(r, i);
}

/* Read a string field, or NULL when the key is absent — the two must stay
 * distinguishable, because "rendered as empty" and "not rendered at all"
 * are different answers and only one of them is honest for a silent
 * emitter. */
static const char *dump_str(const struct json_value *row, const char *key)
{
    const struct json_value *v = row ? json_get(row, key) : NULL;
    if (!v || v->type != JSON_STR)
        return NULL;   /* raw-return-ok:caller-asserts-non-null */
    return json_get_str(v);
}

/* Assert a string field is PRESENT and equal. A missing key must fail as a
 * missing key, never crash the group — a signal is a worse witness than a
 * named assertion, and this suite has to stay readable when it goes red. */
#define ASSERT_FIELD_STR(row, key, want) do {                                 \
    const char *_fv = dump_str((row), (key));                                 \
    ASSERT(_fv != NULL);                                                      \
    ASSERT_STR_EQ(_fv, (want));                                               \
} while (0)

/* ── 1. coverage is reported, never implied ───────────────────────────── */

static int t_zero_records_renders_an_empty_list(void)
{
    int failures = 0;
    TEST_CASE("dump: zero collected records renders an empty list, not a "
              "missing key")
    {
        struct json_value out = {0};
        json_set_object(&out);
        mesh_observation_push_slot_coverage_json(&out, NULL, 0);

        const struct json_value *r = dump_records(&out);
        ASSERT(r != NULL);            /* the key EXISTS */
        ASSERT_EQ(json_size(r), (size_t)0);

        /* Positive control: the same renderer does produce rows when given
         * rows, so the empty above is a measurement and not a renderer that
         * never works. */
        struct mesh_obs_slot one;
        dump_slot_init(&one, "zero1.onion", MESH_OBS_CONFIRMED);
        struct json_value out2 = {0};
        json_set_object(&out2);
        mesh_observation_push_slot_coverage_json(&out2, &one, 1);
        const struct json_value *r2 = dump_records(&out2);
        ASSERT(r2 != NULL);
        ASSERT_EQ(json_size(r2), (size_t)1);

        json_free(&out2);
        json_free(&out);
    } TEST_END
    return failures;
}

/* ── 2. every slot appears, in order, whatever its outcome ────────────── */

static int t_every_slot_appears_in_order(void)
{
    int failures = 0;
    TEST_CASE("dump: every slot renders in order, including one never probed")
    {
        struct mesh_obs_slot s[4];
        dump_slot_init(&s[0], "aaa.onion", MESH_OBS_CONFIRMED);
        dump_slot_init(&s[1], "bbb.onion", MESH_OBS_NOT_PROBED);
        dump_slot_init(&s[2], "ccc.onion", MESH_OBS_DEADLINE);
        dump_slot_init(&s[3], "ddd.onion", MESH_OBS_REFUSED);
        /* Bytes arriving and bytes PARSING are different claims and each
         * row must carry both, or a reader cannot tell a reachable box that
         * served garbage from one it never reached. */
        s[0].parsed = true;
        s[0].fetched_unix = 1756064010;
        s[2].fetched_unix = 1756064030;

        struct json_value out = {0};
        json_set_object(&out);
        mesh_observation_push_slot_coverage_json(&out, s, 4);

        const struct json_value *r = dump_records(&out);
        ASSERT(r != NULL);
        ASSERT_EQ(json_size(r), (size_t)4);

        static const char *const want_onion[4] = {
            "aaa.onion", "bbb.onion", "ccc.onion", "ddd.onion"
        };
        for (size_t i = 0; i < 4; i++) {
            const struct json_value *row = dump_row(&out, i);
            ASSERT(row != NULL);
            const char *onion = dump_str(row, "onion");
            ASSERT(onion != NULL);
            ASSERT_STR_EQ(onion, want_onion[i]);
            const char *fetch = dump_str(row, "fetch");
            ASSERT(fetch != NULL);
            ASSERT_STR_EQ(fetch, mesh_obs_outcome_name(s[i].fetch));
            const struct json_value *parsed = json_get(row, "parsed");
            ASSERT(parsed != NULL);
            ASSERT(parsed->type == JSON_BOOL);
            ASSERT(json_get_bool(parsed) == s[i].parsed);
            const struct json_value *fu = json_get(row, "fetched_unix");
            ASSERT(fu != NULL);
            ASSERT_EQ(json_get_int(fu), s[i].fetched_unix);
        }

        /* NOT_PROBED renders by its own name. It is neither a pass nor a
         * failure and must never be collapsed onto either. */
        ASSERT_FIELD_STR(dump_row(&out, 1), "fetch",
                         mesh_obs_outcome_name(MESH_OBS_NOT_PROBED));
        ASSERT(strcmp(mesh_obs_outcome_name(MESH_OBS_NOT_PROBED),
                      mesh_obs_outcome_name(MESH_OBS_REFUSED)) != 0);

        json_free(&out);
    } TEST_END
    return failures;
}

/* ── 3. a spent budget is never byte-identical to a refusal ───────────── */

static int t_deadline_and_refusal_are_distinguishable(void)
{
    int failures = 0;
    TEST_CASE("dump: elapsed is published on every outcome, so a spent "
              "budget never reads as a refusal")
    {
        struct mesh_obs_slot s[2];
        dump_slot_init(&s[0], "slow.onion", MESH_OBS_DEADLINE);
        s[0].elapsed_us = 30000000;
        s[0].deadline_us = 30000000;
        snprintf(s[0].refusal, sizeof(s[0].refusal), "%s", "");
        dump_slot_init(&s[1], "rst.onion", MESH_OBS_REFUSED);
        s[1].elapsed_us = 1200;
        s[1].deadline_us = 30000000;
        snprintf(s[1].refusal, sizeof(s[1].refusal), "%s", "bad_schema");

        struct json_value out = {0};
        json_set_object(&out);
        mesh_observation_push_slot_coverage_json(&out, s, 2);

        const struct json_value *slow = dump_row(&out, 0);
        const struct json_value *rst = dump_row(&out, 1);
        ASSERT(slow != NULL);
        ASSERT(rst != NULL);

        const struct json_value *se = json_get(slow, "elapsed_us");
        const struct json_value *sd = json_get(slow, "deadline_us");
        const struct json_value *re = json_get(rst, "elapsed_us");
        ASSERT(se != NULL && sd != NULL && re != NULL);
        ASSERT_EQ(json_get_int(se), (int64_t)30000000);
        ASSERT_EQ(json_get_int(sd), (int64_t)30000000);
        ASSERT_EQ(json_get_int(re), (int64_t)1200);

        /* the two rows really are different documents */
        char a[2048], b[2048];
        size_t na = json_write(slow, a, sizeof(a));
        size_t nb = json_write(rst, b, sizeof(b));
        ASSERT(na > 0 && na < sizeof(a));
        ASSERT(nb > 0 && nb < sizeof(b));
        ASSERT(strcmp(a, b) != 0);

        /* and the refusal reason is carried by name, not dropped */
        ASSERT_FIELD_STR(rst, "refusal", "bad_schema");
        ASSERT_FIELD_STR(slow, "refusal", "");

        json_free(&out);
    } TEST_END
    return failures;
}

/* ── 4. the platform is readable beside the onion ─────────────────────── */

static int t_platform_is_rendered_beside_the_onion(void)
{
    int failures = 0;
    TEST_CASE("dump: each collected node's os and arch render beside its "
              "onion")
    {
        struct mesh_obs_slot s[2];
        dump_slot_init(&s[0], "lin.onion", MESH_OBS_CONFIRMED);
        s[0].parsed = true;
        dump_slot_platform(&s[0], "linux", "x86_64");
        dump_slot_init(&s[1], "mac.onion", MESH_OBS_CONFIRMED);
        s[1].parsed = true;
        dump_slot_platform(&s[1], "macos", "arm64");

        struct json_value out = {0};
        json_set_object(&out);
        mesh_observation_push_slot_coverage_json(&out, s, 2);

        const struct json_value *lin = dump_row(&out, 0);
        const struct json_value *mac = dump_row(&out, 1);
        ASSERT(lin != NULL);
        ASSERT(mac != NULL);

        /* beside its onion, in the SAME row — not a separate list a reader
         * would have to join by index */
        ASSERT_FIELD_STR(lin, "onion", "lin.onion");
        ASSERT_FIELD_STR(lin, "record_os", "linux");
        ASSERT_FIELD_STR(lin, "record_arch", "x86_64");
        ASSERT_FIELD_STR(mac, "onion", "mac.onion");
        ASSERT_FIELD_STR(mac, "record_os", "macos");
        ASSERT_FIELD_STR(mac, "record_arch", "arm64");

        json_free(&out);
    } TEST_END
    return failures;
}

static int t_unknown_platform_is_carried_verbatim(void)
{
    int failures = 0;
    TEST_CASE("dump: a platform this build never heard of renders as written")
    {
        /* The whole point of not making these an enum: the first node of a
         * new platform must be visible, not dropped. */
        struct mesh_obs_slot s;
        dump_slot_init(&s, "new.onion", MESH_OBS_CONFIRMED);
        s.parsed = true;
        dump_slot_platform(&s, "haiku", "riscv64");

        /* precondition: this build genuinely does not name that target, so
         * the check below is about an UNKNOWN token and not a known one */
        ASSERT(strcmp(mesh_obs_platform_os(), "haiku") != 0);
        ASSERT(strcmp(mesh_obs_platform_arch(), "riscv64") != 0);

        struct json_value out = {0};
        json_set_object(&out);
        mesh_observation_push_slot_coverage_json(&out, &s, 1);

        const struct json_value *row = dump_row(&out, 0);
        ASSERT(row != NULL);
        ASSERT_FIELD_STR(row, "record_os", "haiku");
        ASSERT_FIELD_STR(row, "record_arch", "riscv64");
        /* not normalised, not folded to "unknown", not blanked */
        const char *ros = dump_str(row, "record_os");
        ASSERT(ros != NULL);
        ASSERT(strcmp(ros, "unknown") != 0);
        ASSERT(strcmp(ros, "") != 0);

        json_free(&out);
    } TEST_END
    return failures;
}

/* ── 5. THE FAIL-ARM: silence stays silence ───────────────────────────── */

static int t_silent_emitter_renders_as_silent(void)
{
    int failures = 0;
    TEST_CASE("dump: an emitter that said nothing renders as having said "
              "nothing, never as this reader's own platform")
    {
        /* Two slots that said nothing, for the two ways it happens: a
         * record that parsed but omitted the fields, and a slot whose fetch
         * never produced a record at all. */
        struct mesh_obs_slot s[2];
        dump_slot_init(&s[0], "quiet.onion", MESH_OBS_CONFIRMED);
        s[0].parsed = true;                    /* os/arch left "" */
        dump_slot_init(&s[1], "dark.onion", MESH_OBS_NOT_PROBED);

        struct json_value out = {0};
        json_set_object(&out);
        mesh_observation_push_slot_coverage_json(&out, s, 2);

        for (size_t i = 0; i < 2; i++) {
            const struct json_value *row = dump_row(&out, i);
            ASSERT(row != NULL);
            const char *os = dump_str(row, "record_os");
            const char *arch = dump_str(row, "record_arch");
            /* the KEY is present — silence is stated, not implied by
             * omission */
            ASSERT(os != NULL);
            ASSERT(arch != NULL);
            ASSERT_STR_EQ(os, "");
            ASSERT_STR_EQ(arch, "");
            /* and it is not this reader's own build target leaking in. On
             * this build mesh_obs_platform_os() is a real token, never "",
             * so the two cannot be confused. */
            ASSERT(strcmp(mesh_obs_platform_os(), "") != 0);
            ASSERT(strcmp(mesh_obs_platform_arch(), "") != 0);
            ASSERT(strcmp(os, mesh_obs_platform_os()) != 0);
            ASSERT(strcmp(arch, mesh_obs_platform_arch()) != 0);
            /* nor a popular default stamped on an unknown box */
            ASSERT(strcmp(os, "linux") != 0);
            ASSERT(strcmp(os, "unknown") != 0);
        }

        json_free(&out);
    } TEST_END
    return failures;
}

/* ── 6. the live dumpers, with nothing to report ──────────────────────── */

static int t_unsampled_node_reports_unverified(void)
{
    int failures = 0;
    TEST_CASE("dump: a node that has never sampled says so, and is not an "
              "empty healthy record")
    {
        struct json_value out = {0};
        ASSERT(mesh_observation_dump_state_json(&out, "mesh_observation"));
        ASSERT(out.type == JSON_OBJ);

        const struct json_value *sampled = json_get(&out, "sampled");
        ASSERT(sampled != NULL);
        ASSERT(sampled->type == JSON_BOOL);
        /* In this process nothing runs the sampler thread, so the honest
         * answer is false with a named reason. */
        ASSERT(json_get_bool(sampled) == false);
        ASSERT_FIELD_STR(&out, "unavailable_reason", "no_sample_yet");
        ASSERT_FIELD_STR(&out, "schema", MESH_OBS_SCHEMA);

        /* An unsampled record must NOT carry a health verdict — the
         * surface deliberately emits no `_health`, because a rollup grants
         * all_ok over zero reporting dumpers. */
        ASSERT(json_get(&out, "_health") == NULL);

        json_free(&out);
    } TEST_END
    return failures;
}

static int t_compose_dump_reports_coverage_first(void)
{
    int failures = 0;
    TEST_CASE("dump: mesh_compose over zero records reports unverified with "
              "its coverage counts")
    {
        struct json_value out = {0};
        ASSERT(mesh_observation_compose_dump_state_json(&out, "mesh_compose"));
        ASSERT(out.type == JSON_OBJ);

        /* coverage first, always — and present even at zero */
        const struct json_value *cov = json_get(&out, "coverage");
        ASSERT(cov != NULL);
        ASSERT(cov->type == JSON_OBJ);
        const struct json_value *offered = json_get(cov, "records_offered");
        ASSERT(offered != NULL);
        ASSERT_EQ(json_get_int(offered), (int64_t)0);

        /* the records list exists even when it is empty */
        const struct json_value *r = dump_records(&out);
        ASSERT(r != NULL);
        ASSERT_EQ(json_size(r), (size_t)0);

        /* zero fresh records is UNVERIFIED, never healthy */
        ASSERT_FIELD_STR(&out, "state", mesh_state_name(MESH_UNVERIFIED));
        ASSERT(json_get(&out, "_health") == NULL);

        /* and the arithmetic that produced it is published beside it */
        ASSERT(json_get(&out, "distinct_identities") != NULL);
        ASSERT(json_get(&out, "agreement") != NULL);
        ASSERT(json_get(&out, "basis") != NULL);

        json_free(&out);
    } TEST_END
    return failures;
}

/* A full array is rendered whole. MESH_OBS_SLOTS_MAX + 1 is the live
 * dumper's own bound (its own record plus the collected set); a renderer
 * that silently truncated would under-report coverage, which is the one
 * direction this surface must never fail in. */
static int t_full_slot_array_renders_whole(void)
{
    int failures = 0;
    TEST_CASE("dump: a full slot array renders every row, none truncated")
    {
        static struct mesh_obs_slot s[MESH_OBS_SLOTS_MAX + 1];
        const size_t n = (size_t)MESH_OBS_SLOTS_MAX + 1;
        for (size_t i = 0; i < n; i++) {
            char onion[MESH_OBS_ONION_MAX];
            snprintf(onion, sizeof(onion), "full%02zu.onion", i);
            dump_slot_init(&s[i], onion, MESH_OBS_CONFIRMED);
            s[i].parsed = true;
            s[i].rec.self.sampled_unix = (int64_t)(1756064000 + i);
            dump_slot_platform(&s[i], (i % 2) ? "macos" : "linux",
                               (i % 2) ? "arm64" : "x86_64");
        }

        struct json_value out = {0};
        json_set_object(&out);
        mesh_observation_push_slot_coverage_json(&out, s, n);

        const struct json_value *r = dump_records(&out);
        ASSERT(r != NULL);
        ASSERT_EQ(json_size(r), n);

        for (size_t i = 0; i < n; i++) {
            const struct json_value *row = dump_row(&out, i);
            ASSERT(row != NULL);
            ASSERT_FIELD_STR(row, "onion", s[i].onion);
            ASSERT_FIELD_STR(row, "record_os", s[i].rec.self.os);
            ASSERT_FIELD_STR(row, "record_arch", s[i].rec.self.arch);
            const struct json_value *ts = json_get(row, "record_sampled_unix");
            ASSERT(ts != NULL);
            ASSERT_EQ(json_get_int(ts), s[i].rec.self.sampled_unix);
        }

        json_free(&out);
    } TEST_END
    return failures;
}

int test_mesh_observation_dump(void)
{
    int failures = 0;
    failures += t_zero_records_renders_an_empty_list();
    failures += t_every_slot_appears_in_order();
    failures += t_deadline_and_refusal_are_distinguishable();
    failures += t_platform_is_rendered_beside_the_onion();
    failures += t_unknown_platform_is_carried_verbatim();
    failures += t_silent_emitter_renders_as_silent();
    failures += t_unsampled_node_reports_unverified();
    failures += t_compose_dump_reports_coverage_first();
    failures += t_full_slot_array_renders_whole();
    return failures;
}
