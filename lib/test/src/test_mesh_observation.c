/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Group `mesh_observation` — the record this node emits about itself.
 *
 * The record is not a verdict. It carries exactly three kinds of field:
 * identity, a measurement WITH its budget attached, and a claim explicitly
 * labelled as a claim. This group proves that shape holds, and proves it with
 * FAIL-ARMS rather than happy paths:
 *
 *   - A deadline may only ever produce the fourth outcome. Silence is never
 *     REFUSED, and `elapsed_us` is populated on all four outcomes — the exact
 *     defect at network_crawler_probe.c:479-498, where latency was assigned
 *     only on success so "3.1 s, alive" was byte-identical to "refused".
 *   - A zeroed struct reads "I did not look", never "it failed".
 *   - An unsampled node has NOTHING to publish and says so; it never serves
 *     an empty-but-healthy document.
 *   - The emitted document contains no verdict vocabulary at all.
 *   - An untrusted peer document is parsed within fixed bounds and every
 *     refusal is named; a malformed field is never guessed at, and a refused
 *     parse leaves the caller's struct untouched.
 *   - Every enum value is reachable and survives the wire as its own token,
 *     so no state here can become a `state == active` that is never true.
 */

#include "test/test_core.h"
#include "services/mesh_observation.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MO_BUF 262144

static char g_mo_a[MO_BUF];
static char g_mo_b[MO_BUF];

/* Bind to the production symbol (defined in mesh_observation_json.c), not
 * to a private copy: a private copy would let the offsets change under the
 * test while every assertion below still passed. */
#define k_mo_back MESH_OBS_ANCHOR_BACK

/* A fully populated record: every field non-default, so a round trip that
 * silently drops one is visible. */
static void mo_make_record(struct mesh_observation *r)
{
    memset(r, 0, sizeof(*r));
    snprintf(r->self.schema, sizeof(r->self.schema), "%s", MESH_OBS_SCHEMA);
    snprintf(r->self.onion, sizeof(r->self.onion), "%s",
             "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvw.onion");
    snprintf(r->self.source_id, sizeof(r->self.source_id), "%s",
             "0123456789abcdef0123456789abcdef01234567");
    /* Deliberately NOT this test host's own platform: a round trip that
     * quietly re-derived the field from the running build instead of
     * carrying the emitter's would still pass if these said "linux". */
    snprintf(r->self.os, sizeof(r->self.os), "%s", "macos");
    snprintf(r->self.arch, sizeof(r->self.arch), "%s", "arm64");
    r->self.tip_height = 2413907;
    snprintf(r->self.tip_hash_hex, sizeof(r->self.tip_hash_hex), "%064llx",
             (unsigned long long)0x1234abcdULL);
    snprintf(r->self.tip_chainwork_hex, sizeof(r->self.tip_chainwork_hex),
             "%064llx", (unsigned long long)0xc41fULL);
    r->self.tip_time_unix = 1756064003;
    for (int i = 0; i < MESH_OBS_ANCHORS; i++) {
        r->self.anchors[i].height = 2413907 - k_mo_back[i];
        r->self.anchors[i].present = true;
        snprintf(r->self.anchors[i].hash_hex,
                 sizeof(r->self.anchors[i].hash_hex), "%064llx",
                 (unsigned long long)(2413907 - k_mo_back[i]));
    }
    r->self.provable_tip = 2413900;
    r->self.provable_tip_published = true;
    r->self.reducer_floor = 2410000;
    r->self.implied_hashrate_ratio_milli = 1043;
    r->self.arrival_window_blocks = 48;
    r->self.listen_stage = MESH_STAGE_READY;
    r->self.tor_requested = true;
    r->self.tor_stub_build = false;
    r->self.cores = 8;
    r->self.ram_bytes = 16638836736LL;
    r->self.rotational_known = true;
    r->self.rotational = true;
    r->self.fsync_us = 72649;
    r->self.pread_us = -1;      /* the measured truncation, published AS -1 */
    snprintf(r->self.hw_fingerprint, sizeof(r->self.hw_fingerprint), "%s",
             "3c6d2f4d3d06d2d3");
    r->self.sampled_unix = 1756064111;
    r->self.sampled_monotonic_us = 998877665544LL;
    r->self.sample_elapsed_us = 412;
    r->self.lock_contended = false;
    snprintf(r->self.unavailable_reason, sizeof(r->self.unavailable_reason),
             "%s", "");

    /* edge 0: confirmed and fast */
    struct mesh_obs_edge *e = &r->edges[0];
    snprintf(e->peer_key_hex, sizeof(e->peer_key_hex), "%s",
             "01a3f2c0d101a3f2c0d101a3f2c0d101a3f2c0d101a3f2c0d101a3f2c0d101a3f2c0d1");
    snprintf(e->peer_onion, sizeof(e->peer_onion), "%s", "peer0.onion");
    e->inbound = false;
    e->transport = MESH_OBS_CONFIRMED;
    e->stage = MESH_STAGE_HANDSHAKE_COMPLETE;
    e->stage_elapsed_us = 38214000;
    e->deadline_us = 120000000;
    e->last_recv_age_us = 4100000;
    e->last_send_age_us = 3300000;
    e->connected_age_us = 918000000;
    e->min_ping_us = 2210000;
    e->claimed_height = 2413907;
    snprintf(e->claimed_tip_hash_hex, sizeof(e->claimed_tip_hash_hex),
             "%064llx", (unsigned long long)0x1234abcdULL);
    e->claim_age_us = 61000000;
    e->claim_verified_locally = true;
    e->header_service = MESH_OBS_CONFIRMED;

    /* edge 1: the normal shape on a 7200-rpm box — the stage is NAMED, the
     * elapsed time equals the budget, and nothing calls it a failure. */
    e = &r->edges[1];
    snprintf(e->peer_key_hex, sizeof(e->peer_key_hex), "%s",
             "01ee9144b201ee9144b201ee9144b201ee9144b201ee9144b201ee9144b201ee9144b2");
    snprintf(e->peer_onion, sizeof(e->peer_onion), "%s", "peer1.onion");
    e->inbound = true;
    e->transport = MESH_OBS_DEADLINE;
    e->stage = MESH_STAGE_VERSION_SENT;
    e->stage_elapsed_us = 120000000;
    e->deadline_us = 120000000;
    e->min_ping_us = 9000000;
    e->claimed_height = -1;
    e->claim_verified_locally = false;
    e->header_service = MESH_OBS_NOT_PROBED;

    r->edge_count = 2;
    r->edges_truncated = 0;
    r->rows_unreadable = 0;
}

static size_t mo_emit(const struct mesh_observation *r, char *buf, size_t n)
{
    struct json_value doc;
    json_init(&doc);
    if (!mesh_observation_emit_json(r, &doc)) { json_free(&doc); return 0; }
    size_t w = json_write(&doc, buf, n);
    json_free(&doc);
    return w;
}

/* ── the shape of the record ──────────────────────────────────────────── */

static int t_constants_are_the_published_contract(void)
{
    int failures = 0;
    TEST_CASE("mesh_observation: the record's bounds are fixed and published")
    {
        ASSERT_STR_EQ(MESH_OBS_SCHEMA, "zcl.mesh.observation.v1");
        ASSERT_EQ(MESH_OBS_EDGES_MAX, 32);      /* connman's ceiling */
        ASSERT_EQ(MESH_OBS_ANCHORS, 5);
        ASSERT_EQ(MESH_OBS_KEYHEX, NET_SERVICE_KEY_SIZE * 2 + 1);
        /* the ladder is deepest-last and strictly increasing */
        ASSERT_EQ(k_mo_back[0], 0);
        for (int i = 1; i < MESH_OBS_ANCHORS; i++)
            ASSERT(k_mo_back[i] > k_mo_back[i - 1]);
        ASSERT_EQ(k_mo_back[MESH_OBS_ANCHORS - 1], 144);
        /* nothing grows: the record is a fixed-size struct */
        ASSERT(sizeof(struct mesh_observation) < 32768);
    } TEST_END
    return failures;
}

/* THE WEAK-NODE RULE. Four outcomes; a deadline may only ever produce the
 * fourth. FAIL-ARM: if DEADLINE ever aliased REFUSED, or if NOT_PROBED were
 * given a non-zero value, these fire. */
static int t_four_outcomes_and_a_zeroed_struct(void)
{
    int failures = 0;
    TEST_CASE("mesh_observation: four outcomes, and zeroed means 'I did not look'")
    {
        ASSERT_EQ((int)MESH_OBS_NOT_PROBED, 0);
        ASSERT(MESH_OBS_CONFIRMED != MESH_OBS_NOT_PROBED);
        ASSERT(MESH_OBS_REFUSED   != MESH_OBS_DEADLINE);
        ASSERT(MESH_OBS_REFUSED   != MESH_OBS_NOT_PROBED);

        ASSERT_STR_EQ(mesh_obs_outcome_name(MESH_OBS_NOT_PROBED), "not_probed");
        ASSERT_STR_EQ(mesh_obs_outcome_name(MESH_OBS_CONFIRMED), "confirmed");
        ASSERT_STR_EQ(mesh_obs_outcome_name(MESH_OBS_REFUSED), "refused");
        /* the deadline token says WHOSE budget ran out, not that the peer
         * did anything wrong */
        ASSERT_STR_EQ(mesh_obs_outcome_name(MESH_OBS_DEADLINE),
                      "deadline_expired");
        ASSERT(strcmp(mesh_obs_outcome_name(MESH_OBS_DEADLINE),
                      mesh_obs_outcome_name(MESH_OBS_REFUSED)) != 0);

        /* all four names distinct */
        for (int i = 0; i <= (int)MESH_OBS_DEADLINE; i++)
            for (int j = i + 1; j <= (int)MESH_OBS_DEADLINE; j++)
                ASSERT(strcmp(mesh_obs_outcome_name((enum mesh_obs_outcome)i),
                              mesh_obs_outcome_name((enum mesh_obs_outcome)j))
                       != 0);

        /* a zeroed edge is NOT_PROBED — reachability is meaningless, not false */
        struct mesh_obs_edge z;
        memset(&z, 0, sizeof(z));
        ASSERT(z.transport == MESH_OBS_NOT_PROBED);
        ASSERT(z.header_service == MESH_OBS_NOT_PROBED);
    } TEST_END
    return failures;
}

/* ANNOUNCEMENTS ARE PROMISES. READY sits after descriptor, rendezvous,
 * circuit and listen; a partial stage is its own named state. FAIL-ARM: a
 * build that made READY reachable before LISTEN reorders these. */
static int t_promise_ladder_is_ordered_and_named(void)
{
    int failures = 0;
    TEST_CASE("mesh_observation: READY comes only after all four listen stages")
    {
        ASSERT(MESH_STAGE_NONE < MESH_STAGE_DESCRIPTOR);
        ASSERT(MESH_STAGE_DESCRIPTOR < MESH_STAGE_RENDEZVOUS);
        ASSERT(MESH_STAGE_RENDEZVOUS < MESH_STAGE_CIRCUIT);
        ASSERT(MESH_STAGE_CIRCUIT < MESH_STAGE_LISTEN);
        ASSERT(MESH_STAGE_LISTEN < MESH_STAGE_READY);
        /* the dial ladder is likewise ordered and terminates in SERVING */
        ASSERT(MESH_STAGE_DIALED < MESH_STAGE_VERSION_SENT);
        ASSERT(MESH_STAGE_VERSION_SENT < MESH_STAGE_VERSION_RECVD);
        ASSERT(MESH_STAGE_VERSION_RECVD < MESH_STAGE_VERACK);
        ASSERT(MESH_STAGE_VERACK < MESH_STAGE_HANDSHAKE_COMPLETE);
        ASSERT(MESH_STAGE_HANDSHAKE_COMPLETE < MESH_STAGE_SERVING);

        /* every stage is REACHABLE by name and no two share one — a partial
         * stage can always be reported as itself instead of being rounded to
         * READY or to a failure */
        for (int i = MESH_STAGE_NONE; i <= MESH_STAGE_SERVING; i++) {
            const char *n = mesh_obs_stage_name((enum mesh_obs_stage)i);
            ASSERT(n != NULL);
            ASSERT(n[0] != '\0');
            for (int j = i + 1; j <= MESH_STAGE_SERVING; j++)
                ASSERT(strcmp(n, mesh_obs_stage_name((enum mesh_obs_stage)j))
                       != 0);
        }
        ASSERT_STR_EQ(mesh_obs_stage_name(MESH_STAGE_READY), "ready");
        ASSERT_STR_EQ(mesh_obs_stage_name(MESH_STAGE_VERSION_SENT),
                      "version_sent");
    } TEST_END
    return failures;
}

/* ── the emitted document ─────────────────────────────────────────────── */

/* FAIL-ARM for the whole design. If anybody ever adds a rollup field, one of
 * these substrings appears and the test fires. */
static int t_document_has_no_verdict_vocabulary(void)
{
    int failures = 0;
    TEST_CASE("mesh_observation: the emitted document pronounces nothing")
    {
        struct mesh_observation r;
        mo_make_record(&r);
        size_t w = mo_emit(&r, g_mo_a, sizeof(g_mo_a));
        ASSERT(w > 0);
        ASSERT(w < sizeof(g_mo_a));      /* not truncated */

        static const char *const banned[] = {
            "\"pass\"", "\"fail\"", "\"verdict\"", "\"healthy\"", "\"ok\":",
            "\"mesh\":", "\"_health\"", "\"all_ok\"", "\"good_peers\"",
            "\"reachable\":", "4/4",
        };
        for (size_t i = 0; i < sizeof(banned) / sizeof(banned[0]); i++) {
            if (strstr(g_mo_a, banned[i]) != NULL) {
                printf("FAIL (verdict vocabulary %s in the record)\n",
                       banned[i]);
                failures++;
                goto _test_next;
            }
        }
        /* positive control: the scan works, and the document really is the
         * observation document */
        ASSERT(strstr(g_mo_a, "\"schema\"") != NULL);
        ASSERT(strstr(g_mo_a, MESH_OBS_SCHEMA) != NULL);
        /* every measurement ships beside its budget */
        ASSERT(strstr(g_mo_a, "\"stage_elapsed_us\"") != NULL);
        ASSERT(strstr(g_mo_a, "\"deadline_us\"") != NULL);
        /* a claim is labelled as a claim */
        ASSERT(strstr(g_mo_a, "\"claimed_height\"") != NULL);
        ASSERT(strstr(g_mo_a, "\"claim_verified_locally\"") != NULL);
        /* coverage is published, so a reader can see what was NOT read */
        ASSERT(strstr(g_mo_a, "\"edges_truncated\"") != NULL);
        ASSERT(strstr(g_mo_a, "\"rows_unreadable\"") != NULL);
    } TEST_END
    return failures;
}

/* Enums cross the wire as tokens, never as integers: a reader on an older
 * build must be able to refuse "deadline_expired" by name rather than
 * mis-decode a 3. FAIL-ARM: an integer encoding drops these substrings. */
static int t_enums_cross_the_wire_as_tokens(void)
{
    int failures = 0;
    TEST_CASE("mesh_observation: outcomes and stages ship as named tokens")
    {
        struct mesh_observation r;
        mo_make_record(&r);
        ASSERT(mo_emit(&r, g_mo_a, sizeof(g_mo_a)) > 0);

        ASSERT(strstr(g_mo_a, "\"confirmed\"") != NULL);
        ASSERT(strstr(g_mo_a, "\"deadline_expired\"") != NULL);
        ASSERT(strstr(g_mo_a, "\"not_probed\"") != NULL);
        ASSERT(strstr(g_mo_a, "\"handshake_complete\"") != NULL);
        ASSERT(strstr(g_mo_a, "\"version_sent\"") != NULL);
        ASSERT(strstr(g_mo_a, "\"ready\"") != NULL);
        /* the slow edge is published as reachable-with-a-spent-budget, and
         * nowhere as refused */
        ASSERT(strstr(g_mo_a, "\"refused\"") == NULL);
    } TEST_END
    return failures;
}

/* A -1 that means "the probe never ran" must survive as -1. If it were
 * normalised to 0 the reader would believe the box did a 0 us pread. This is
 * measured reality on the fleet's HDD boxes: fsync 72649 us, pread -1. */
static int t_round_trip_is_byte_stable(void)
{
    int failures = 0;
    TEST_CASE("mesh_observation: emit -> parse -> emit is byte-stable")
    {
        struct mesh_observation r;
        mo_make_record(&r);
        size_t w1 = mo_emit(&r, g_mo_a, sizeof(g_mo_a));
        ASSERT(w1 > 0 && w1 < sizeof(g_mo_a));

        struct mesh_observation back;
        memset(&back, 0xCC, sizeof(back));
        char reason[32];
        bool ok = mesh_observation_parse_json(g_mo_a, w1, &back, reason);
        ASSERT(ok);

        ASSERT_EQ(back.self.pread_us, -1);          /* never rewritten to 0 */
        ASSERT_EQ(back.self.fsync_us, 72649);
        /* The EMITTER's build target survives, not the reader's. */
        ASSERT_STR_EQ(back.self.os, "macos");
        ASSERT_STR_EQ(back.self.arch, "arm64");
        ASSERT_EQ(back.edge_count, 2);
        ASSERT(back.edges[1].transport == MESH_OBS_DEADLINE);
        ASSERT(back.edges[1].header_service == MESH_OBS_NOT_PROBED);
        ASSERT(back.edges[1].stage == MESH_STAGE_VERSION_SENT);
        ASSERT_EQ(back.edges[1].stage_elapsed_us, back.edges[1].deadline_us);
        ASSERT_EQ(back.edges[1].claimed_height, -1);
        ASSERT(back.self.listen_stage == MESH_STAGE_READY);
        ASSERT_STR_EQ(back.self.tip_chainwork_hex, r.self.tip_chainwork_hex);
        for (int i = 0; i < MESH_OBS_ANCHORS; i++) {
            ASSERT(back.self.anchors[i].present);
            ASSERT_EQ(back.self.anchors[i].height, r.self.anchors[i].height);
            ASSERT_STR_EQ(back.self.anchors[i].hash_hex,
                          r.self.anchors[i].hash_hex);
        }

        size_t w2 = mo_emit(&back, g_mo_b, sizeof(g_mo_b));
        ASSERT_EQ(w1, w2);
        ASSERT_STR_EQ(g_mo_a, g_mo_b);
    } TEST_END
    return failures;
}

/* PLATFORM TRUTH. `tor_stub_build` cannot carry it alone: a Linux box built
 * with plain `make` and a macOS box whose platform HAS no embedded Tor emit
 * the identical `true`, and a reader that cannot separate them is guessing
 * about which machines can ever be reached.
 *
 * Three arms, because the field is only worth having if all three hold:
 *   - this build states its own target, and never as "";
 *   - a token from a platform THIS BUILD HAS NEVER HEARD OF survives the
 *     wire verbatim, so the mesh does not go blind on the first node of the
 *     next platform;
 *   - a malformed token is refused under its OWN name.
 */
static int t_platform_is_named_and_survives_the_wire(void)
{
    int failures = 0;
    TEST_CASE("mesh_observation: a node names the platform it was built for")
    {
        /* 1. this build answers, and "" is never the answer */
        const char *os = mesh_obs_platform_os();
        const char *arch = mesh_obs_platform_arch();
        ASSERT(os != NULL && os[0] != '\0');
        ASSERT(arch != NULL && arch[0] != '\0');
        ASSERT(mesh_obs_platform_token_ok(os));
        ASSERT(mesh_obs_platform_token_ok(arch));
        ASSERT(strlen(os) < MESH_OBS_PLATFORM_MAX);
        ASSERT(strlen(arch) < MESH_OBS_PLATFORM_MAX);

        /* the token vocabulary is bounded and lowercase; "" means the
         * emitter said nothing and is a real, valid value */
        ASSERT(mesh_obs_platform_token_ok(""));
        ASSERT(mesh_obs_platform_token_ok("macos"));
        ASSERT(mesh_obs_platform_token_ok("windows"));
        ASSERT(mesh_obs_platform_token_ok("x86_64"));
        ASSERT(mesh_obs_platform_token_ok("MacOS") == false);
        ASSERT(mesh_obs_platform_token_ok("mac os") == false);
        ASSERT(mesh_obs_platform_token_ok("mac.os") == false);
        ASSERT(mesh_obs_platform_token_ok(NULL) == false);
        ASSERT(mesh_obs_platform_token_ok("abcdefghijklmnop") == false);

        /* 2. the tokens reach the document as their own keys */
        struct mesh_observation r;
        mo_make_record(&r);
        size_t w = mo_emit(&r, g_mo_a, sizeof(g_mo_a));
        ASSERT(w > 0 && w < sizeof(g_mo_a));
        ASSERT(strstr(g_mo_a, "\"os\"") != NULL);
        ASSERT(strstr(g_mo_a, "\"arch\"") != NULL);
        ASSERT(strstr(g_mo_a, "\"macos\"") != NULL);
        ASSERT(strstr(g_mo_a, "\"arm64\"") != NULL);

        /* 3. a platform this build has never heard of is CARRIED, not
         * refused. FAIL-ARM against anyone turning this into a closed enum:
         * that change would drop this document entirely, which is exactly
         * how a new platform becomes invisible to the fleet. */
        static char future[512];
        snprintf(future, sizeof(future),
                 "{\"schema\":\"%s\",\"self\":{\"os\":\"plan9\","
                 "\"arch\":\"riscv64\"},\"edges\":[],\"coverage\":"
                 "{\"edge_count\":0,\"edges_truncated\":0,"
                 "\"rows_unreadable\":0}}", MESH_OBS_SCHEMA);
        struct mesh_observation fwd;
        char freason[MESH_OBS_REASON_MAX];
        memset(freason, 0, sizeof(freason));
        ASSERT(mesh_observation_parse_json(future, strlen(future), &fwd,
                                           freason));
        ASSERT_STR_EQ(fwd.self.os, "plan9");
        ASSERT_STR_EQ(fwd.self.arch, "riscv64");

        /* 4. an emitter that says nothing is distinguishable from one that
         * says something — "" survives as "", never as a guess */
        static char silent[512];
        snprintf(silent, sizeof(silent),
                 "{\"schema\":\"%s\",\"self\":{},\"edges\":[],\"coverage\":"
                 "{\"edge_count\":0,\"edges_truncated\":0,"
                 "\"rows_unreadable\":0}}", MESH_OBS_SCHEMA);
        struct mesh_observation quiet;
        char qreason[MESH_OBS_REASON_MAX];
        memset(qreason, 0, sizeof(qreason));
        ASSERT(mesh_observation_parse_json(silent, strlen(silent), &quiet,
                                           qreason));
        ASSERT_STR_EQ(quiet.self.os, "");
        ASSERT_STR_EQ(quiet.self.arch, "");

        /* 5. a MALFORMED token is refused under its own name, and the
         * caller's struct is left untouched */
        static char bad[512];
        snprintf(bad, sizeof(bad),
                 "{\"schema\":\"%s\",\"self\":{\"os\":\"Linux!\"},"
                 "\"edges\":[],\"coverage\":{\"edge_count\":0,"
                 "\"edges_truncated\":0,\"rows_unreadable\":0}}",
                 MESH_OBS_SCHEMA);
        struct mesh_observation sentinel, out;
        memset(&sentinel, 0x5A, sizeof(sentinel));
        memcpy(&out, &sentinel, sizeof(out));
        char breason[MESH_OBS_REASON_MAX];
        memset(breason, 0, sizeof(breason));
        ASSERT(mesh_observation_parse_json(bad, strlen(bad), &out,
                                           breason) == false);
        ASSERT_STR_EQ(breason, "bad_platform_token");
        ASSERT(memcmp(&out, &sentinel, sizeof(out)) == 0);
    } TEST_END
    return failures;
}

/* Truncation must be REPRESENTABLE and published, never silent. A 32-edge
 * record that dropped rows says so. */
static int t_truncation_is_published_not_hidden(void)
{
    int failures = 0;
    TEST_CASE("mesh_observation: a truncated edge list publishes the shortfall")
    {
        struct mesh_observation r;
        mo_make_record(&r);
        for (int i = 2; i < MESH_OBS_EDGES_MAX; i++) {
            r.edges[i] = r.edges[0];
            snprintf(r.edges[i].peer_onion, sizeof(r.edges[i].peer_onion),
                     "peer%d.onion", i);
        }
        r.edge_count = MESH_OBS_EDGES_MAX;
        r.edges_truncated = 7;
        r.rows_unreadable = 3;

        size_t w = mo_emit(&r, g_mo_a, sizeof(g_mo_a));
        ASSERT(w > 0 && w < sizeof(g_mo_a));

        struct mesh_observation back;
        char reason[32];
        ASSERT(mesh_observation_parse_json(g_mo_a, w, &back, reason));
        ASSERT_EQ(back.edge_count, MESH_OBS_EDGES_MAX);
        ASSERT_EQ(back.edges_truncated, 7);
        ASSERT_EQ(back.rows_unreadable, 3);
    } TEST_END
    return failures;
}

/* ── parsing an UNTRUSTED peer document ───────────────────────────────── */

/* `len` < 0 means "measure the literal"; 0 is a genuine zero-length body. */
struct mo_refusal_case { const char *label; const char *body; long len; };

static size_t mo_case_len(const struct mo_refusal_case *c)
{
    return c->len < 0 ? strlen(c->body) : (size_t)c->len;
}

static int t_parse_refuses_by_name_and_leaves_out_untouched(void)
{
    int failures = 0;
    TEST_CASE("mesh_observation: every malformed document is refused BY NAME")
    {
        /* a valid document to mutate from */
        struct mesh_observation good;
        mo_make_record(&good);
        size_t gw = mo_emit(&good, g_mo_a, sizeof(g_mo_a));
        ASSERT(gw > 0);

        /* oversize: a 4 KB onion string, and 10 000 declared edges */
        static char huge_onion[8192];
        int hn = snprintf(huge_onion, sizeof(huge_onion),
                          "{\"schema\":\"%s\",\"self\":{\"onion\":\"",
                          MESH_OBS_SCHEMA);
        for (int i = 0; i < 4096; i++) huge_onion[hn + i] = 'a';
        hn += 4096;
        hn += snprintf(huge_onion + hn, sizeof(huge_onion) - (size_t)hn,
                       "\"}}");

        static char many_edges[131072];
        int mn = snprintf(many_edges, sizeof(many_edges),
                          "{\"schema\":\"%s\",\"self\":{},\"edges\":[",
                          MESH_OBS_SCHEMA);
        for (int i = 0; i < 10000 && mn < (int)sizeof(many_edges) - 32; i++)
            mn += snprintf(many_edges + mn, sizeof(many_edges) - (size_t)mn,
                           "%s{}", i ? "," : "");
        mn += snprintf(many_edges + mn, sizeof(many_edges) - (size_t)mn, "]}");

        static char bad_hex[512];
        snprintf(bad_hex, sizeof(bad_hex),
                 "{\"schema\":\"%s\",\"self\":{\"anchors\":"
                 "[{\"back\":0,\"height\":10,\"hash\":\"zzzz\","
                 "\"present\":true}]}}", MESH_OBS_SCHEMA);

        static char neg_height[512];
        snprintf(neg_height, sizeof(neg_height),
                 "{\"schema\":\"%s\",\"self\":{\"anchors\":"
                 "[{\"back\":0,\"height\":-9,\"hash\":\"ab\","
                 "\"present\":true}]}}", MESH_OBS_SCHEMA);

        static char truncated[256];
        size_t tlen = gw < sizeof(truncated) - 1 ? gw / 2 : 200;
        memcpy(truncated, g_mo_a, tlen);
        truncated[tlen] = '\0';

        struct mo_refusal_case cases[] = {
            { "empty",        "",                 0 },
            { "not_json",     "not json at all", -1 },
            { "not_object",   "[1,2,3]",         -1 },
            { "wrong_schema",
              "{\"schema\":\"zcl.mesh.observation.v99\",\"self\":{}}", -1 },
            { "no_schema",    "{\"self\":{}}",    -1 },
            { "truncated",    truncated,     (long)tlen },
            { "huge_onion",   huge_onion,    (long)hn },
            { "many_edges",   many_edges,    (long)mn },
            { "bad_hex",      bad_hex,           -1 },
            { "neg_height",   neg_height,        -1 },
        };
        size_t ncases = sizeof(cases) / sizeof(cases[0]);

        /* the sentinel the parser must not disturb */
        struct mesh_observation sentinel;
        memset(&sentinel, 0x5A, sizeof(sentinel));

        char reasons[16][32];
        for (size_t i = 0; i < ncases; i++) {
            struct mesh_observation out;
            memcpy(&out, &sentinel, sizeof(out));
            char reason[32];
            memset(reason, 0, sizeof(reason));
            bool ok = mesh_observation_parse_json(cases[i].body,
                                                  mo_case_len(&cases[i]),
                                                  &out, reason);
            if (ok) {
                printf("FAIL (%s was ACCEPTED)\n", cases[i].label);
                failures++;
                goto _test_next;
            }
            if (memcmp(&out, &sentinel, sizeof(out)) != 0) {
                printf("FAIL (%s modified the caller's struct)\n",
                       cases[i].label);
                failures++;
                goto _test_next;
            }
            if (reason[0] == '\0') {
                printf("FAIL (%s refused without naming a reason)\n",
                       cases[i].label);
                failures++;
                goto _test_next;
            }
            /* a token, not a sentence, and NUL-terminated inside 32 bytes */
            size_t rl = 0;
            while (rl < sizeof(reason) && reason[rl] != '\0') rl++;
            if (rl >= sizeof(reason)) {
                printf("FAIL (%s reason token is unterminated)\n",
                       cases[i].label);
                failures++;
                goto _test_next;
            }
            snprintf(reasons[i], sizeof(reasons[i]), "%s", reason);
        }

        /* the refusals must DISCRIMINATE: a single catch-all token would let
         * an operator mistake an oversize document for a truncated one */
        int distinct = 0;
        for (size_t i = 0; i < ncases; i++) {
            bool dup = false;
            for (size_t j = 0; j < i; j++)
                if (strcmp(reasons[i], reasons[j]) == 0) dup = true;
            if (!dup) distinct++;
        }
        ASSERT(distinct >= 5);

        /* positive control: the SAME parser accepts the good document, so the
         * refusals above are discrimination and not a parser that says no to
         * everything */
        struct mesh_observation okrec;
        char okreason[32];
        ASSERT(mesh_observation_parse_json(g_mo_a, gw, &okrec, okreason));
    } TEST_END
    return failures;
}

/* An UNSAMPLED node has nothing to publish and must say so. FAIL-ARM for the
 * empty-but-healthy document: a zeroed record that serialises to something a
 * reader would treat as a fresh observation. */
static int t_unsampled_node_publishes_nothing_usable(void)
{
    int failures = 0;
    TEST_CASE("mesh_observation: an unsampled node has nothing to publish")
    {
        /* before the first tick the snapshot must decline outright */
        struct mesh_observation snap;
        memset(&snap, 0x11, sizeof(snap));
        bool have = mesh_observation_snapshot(&snap);
        ASSERT(have == false);
        ASSERT(mesh_observation_snapshot(NULL) == false);

        /* and even if a zeroed record were serialised, it carries
         * sampled_unix == 0, which every reader's freshness step rejects */
        struct mesh_observation zero;
        memset(&zero, 0, sizeof(zero));
        size_t w = mo_emit(&zero, g_mo_a, sizeof(g_mo_a));
        ASSERT(w > 0);
        ASSERT_EQ(zero.self.sampled_unix, 0);
        ASSERT_EQ(zero.edge_count, 0);
        ASSERT(strstr(g_mo_a, "\"sampled_unix\":0") != NULL);
        ASSERT(strstr(g_mo_a, "\"healthy\"") == NULL);
        ASSERT(strstr(g_mo_a, "\"ok\":") == NULL);
    } TEST_END
    return failures;
}

/* The collector reports coverage honestly before it has collected anything:
 * zero slots, not a full array of defaults. */
static int t_collector_reports_zero_before_it_collects(void)
{
    int failures = 0;
    TEST_CASE("mesh_observation: an idle collector reports zero, not defaults")
    {
        struct mesh_obs_slot slots[8];
        memset(slots, 0x33, sizeof(slots));
        int n = mesh_observation_collect_snapshot(slots, 8);
        ASSERT(n >= 0);
        ASSERT(n <= 8);
        ASSERT_EQ(n, 0);
        /* a zero-capacity call must not write and must not fault */
        ASSERT_EQ(mesh_observation_collect_snapshot(NULL, 0), 0);
    } TEST_END
    return failures;
}

/* The sampler runs on a bare process without a connman: it must decline
 * honestly rather than publish zeros as if they were observations. */
static int t_sampler_declines_honestly_without_a_connman(void)
{
    int failures = 0;
    TEST_CASE("mesh_observation: a sampler with nothing to read publishes no zeros")
    {
        mesh_observation_sample_once();

        struct mesh_observation snap;
        memset(&snap, 0, sizeof(snap));
        if (mesh_observation_snapshot(&snap)) {
            /* if it did publish, the record must be self-describing and
             * bounded, and must name why it is empty */
            ASSERT_STR_EQ(snap.self.schema, MESH_OBS_SCHEMA);
            ASSERT(snap.edge_count >= 0);
            ASSERT(snap.edge_count <= MESH_OBS_EDGES_MAX);
            ASSERT(snap.edges_truncated >= 0);
            ASSERT(snap.rows_unreadable >= 0);
            ASSERT(snap.self.sample_elapsed_us >= 0);
            if (snap.edge_count == 0)
                ASSERT(snap.self.unavailable_reason[0] != '\0');
        }
        /* either way the call returned: no blocking lock on the sample path */
    } TEST_END
    return failures;
}

int test_mesh_observation(void)
{
    int failures = 0;
    failures += t_constants_are_the_published_contract();
    failures += t_four_outcomes_and_a_zeroed_struct();
    failures += t_promise_ladder_is_ordered_and_named();
    failures += t_document_has_no_verdict_vocabulary();
    failures += t_enums_cross_the_wire_as_tokens();
    failures += t_round_trip_is_byte_stable();
    failures += t_platform_is_named_and_survives_the_wire();
    failures += t_truncation_is_published_not_hidden();
    failures += t_parse_refuses_by_name_and_leaves_out_untouched();
    failures += t_unsampled_node_publishes_nothing_usable();
    failures += t_collector_reports_zero_before_it_collects();
    failures += t_sampler_declines_honestly_without_a_connman();
    return failures;
}
