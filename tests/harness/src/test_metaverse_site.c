/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_metaverse_site — the metaverse onion/HTTPS site gate
 * (contexts/commons/controllers/src/metaverse_site_controller.c +
 * contexts/explorer/views/src/metaverse_view{,_pages}.c).
 *
 * Coverage:
 *   1. Route coverage: every route in the contract (/metaverse,
 *      /metaverse/property[+kind filter], /metaverse/space,
 *      /metaverse/commons) renders a complete, non-trivial HTTP response
 *      from one fixture datadir — the landing with the mission text and
 *      section links, the property page with kind/settlement markers, the
 *      space page with the fixture descriptor, and the commons page with
 *      its SIMULATION label.
 *   2. PROJECTION AGREEMENT (the adversarial one): the same fixture state
 *      is read by the typed commands (metaverse.property.list,
 *      metaverse.space.show, zcode.commons.status) and by the site — the
 *      kind/settlement facts, the descriptor protocol root, and the
 *      commons verification status rendered into the HTML match the
 *      command projections exactly. No website database, no second truth.
 *   3. Empty projections: a datadir with no workspace CAS renders the
 *      space and property pages as honest empties (named, never padded),
 *      and the commons page with the unknown/zero summary.
 *   4. Honest failures: an unknown /metaverse route is a named 404 that
 *      escapes the attacker-controlled path; an unknown kind filter is a
 *      named 400, never a silently unfiltered page.
 *   5. Bounded output: every page fits the onion response budget.
 *
 * Fixtures run in-process on ./test-tmp datadirs (the test_zcode_site
 * pattern). The space fixture is a committed service_descriptor.v1 —
 * committing one needs no node identity, unlike a space manifest. */

#include "test/test_core.h"

#include "command/native_command.h"

#include "controllers/metaverse_site_controller.h"

#include "base/hex.h"
#include "json/json.h"
#include "services/metaverse_space_service.h"
#include "vcs/space.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MS_CHECK(name, expr) do {                                     \
    if (expr) { printf("  metaverse_site: %s... OK\n", (name)); }     \
    else { printf("  metaverse_site: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* ── request helper ────────────────────────────────────────────────── */

static uint8_t *g_resp = NULL;
#define MS_RESP_CAP (160u * 1024u)

/* Issue one GET against the fixture datadir; NUL-terminates the response
 * (responses here are always short of the cap in these fixtures). */
static const char *ms_get(const char *dd, const char *path, size_t *len_out)
{
    size_t n = metaverse_site_handle_request("GET", path, NULL, 0, g_resp,
                                             MS_RESP_CAP - 1, dd);
    /* snprintf-style would-be length: clamp before indexing g_resp. */
    if (n >= MS_RESP_CAP)
        n = MS_RESP_CAP - 1;
    g_resp[n] = '\0';
    if (len_out)
        *len_out = n;
    return (const char *)g_resp;
}

/* ── in-process command runner (the test_zcode_site pattern) ───────── */

struct ms_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void ms_cmd_init(struct ms_cmd *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.metaverse_site_test.v1");
}

static void ms_cmd_free(struct ms_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Commit one service_descriptor.v1 into <dd>/zcode's workspace CAS (the
 * metaverse.space.plan/commit path minus the identity requirements a
 * manifest carries). root_hex_out (65) gets the object root. */
static bool ms_commit_descriptor(const char *dd, uint8_t seed,
                                 char root_hex_out[65])
{
    char workspace[512];
    int n = snprintf(workspace, sizeof(workspace), "%s/zcode", dd);
    if (n <= 0 || (size_t)n >= sizeof(workspace))
        return false;
    /* The commit's CAS init creates .zvcs under the workspace but not the
     * workspace itself — the same precondition the publish flow meets. */
    if (mkdir(workspace, 0755) != 0 && errno != EEXIST)
        return false;

    struct vcs_service_descriptor_v1 descriptor;
    memset(&descriptor, 0, sizeof(descriptor));
    descriptor.schema_version = VCS_SERVICE_DESCRIPTOR_VERSION;
    for (size_t i = 0; i < 32; i++)
        descriptor.protocol_root[i] = (uint8_t)(seed + i);
    descriptor.read_verbs = VCS_SERVICE_VERB_FETCH | VCS_SERVICE_VERB_LIST;

    struct metaverse_space_plan_out plan;
    struct zcl_result planned =
        metaverse_space_service_plan(&descriptor, &plan);
    if (!planned.ok)
        return false;
    struct metaverse_space_commit_out committed;
    struct zcl_result result = metaverse_space_service_commit(
        workspace, &descriptor, plan.plan_token, true, &committed);
    if (!result.ok)
        return false;
    snprintf(root_hex_out, 65, "%s", committed.object_root);
    return true;
}

/* ══ 1+2. route coverage + projection agreement ═══════════════════════ */

static int t_routes_and_agreement(const char *dd)
{
    int failures = 0;
    char root_hex[65];
    bool seeded = ms_commit_descriptor(dd, 0x41, root_hex);
    MS_CHECK("fixture: service descriptor committed", seeded);
    if (!seeded)
        return failures + 1;
    size_t len = 0;

    /* Route coverage. */
    const char *r = ms_get(dd, "/metaverse", &len);
    MS_CHECK("route /metaverse: 200 + mission + links + SIMULATION",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "nobody owns the world they build in") &&
             strstr(r, "/metaverse/property") &&
             strstr(r, "/metaverse/space") &&
             strstr(r, "/metaverse/commons") &&
             strstr(r, "SIMULATION"));

    r = ms_get(dd, "/metaverse/property", &len);
    MS_CHECK("route /metaverse/property: 200 + kinds + settlement classes",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "Sovereign Property") &&
             strstr(r, "zcode_package") && strstr(r, "znam_name") &&
             strstr(r, "content_addressed") &&
             strstr(r, "proof_of_work") &&
             strstr(r, "local_declaration"));

    r = ms_get(dd, "/metaverse/property?kind=zcode_package", &len);
    MS_CHECK("route /metaverse/property?kind=zcode_package: 200 filtered",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "filtered to kind") &&
             strstr(r, "not scanned: excluded by the kind filter"));

    r = ms_get(dd, "/metaverse/space", &len);
    MS_CHECK("route /metaverse/space: 200 + descriptor count + root",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "Published Spaces") &&
             strstr(r, "1 service descriptor") &&
             strstr(r, "No published spaces known locally"));

    r = ms_get(dd, "/metaverse/commons", &len);
    MS_CHECK("route /metaverse/commons: 200 + SIMULATION + empty summary",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "ZC23 Living Commons") &&
             strstr(r, "SIMULATION") &&
             strstr(r, "verification status</b><span class='val'>unknown")
             &&
             strstr(r, "No epochs in the workspace CAS yet"));

    /* ── projection agreement: commands vs pages over the same datadir ── */

    /* metaverse.property.list ↔ /metaverse/property (kind + settlement). */
    struct ms_cmd c;
    ms_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    zcl_native_handle_metaverse_property_list(&c.request, &c.reply);
    const struct json_value *kinds = json_get(&c.reply.data, "kinds");
    bool cmd_znam_pow = false;
    for (size_t i = 0; kinds && i < json_size(kinds); i++) {
        const struct json_value *row = json_at(kinds, i);
        const char *k = row ? json_get_str(json_get(row, "kind")) : NULL;
        const char *s =
            row ? json_get_str(json_get(row, "settlement")) : NULL;
        if (k && s && strcmp(k, "znam_name") == 0 &&
            strcmp(s, "proof_of_work") == 0)
            cmd_znam_pow = true;
    }
    int64_t cmd_kinds_scanned =
        json_get_int(json_get(&c.reply.data, "kinds_scanned"));
    r = ms_get(dd, "/metaverse/property", &len);
    MS_CHECK("agreement: property list kinds == property page",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED && cmd_znam_pow &&
             cmd_kinds_scanned > 0 &&
             strstr(r, "znam_name") && strstr(r, "proof_of_work"));
    ms_cmd_free(&c);

    /* zcode.commons.status ↔ /metaverse/commons (status + counts). */
    char workspace[512];
    snprintf(workspace, sizeof(workspace), "%s/zcode", dd);
    ms_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "workspace", workspace);
    zcl_native_handle_zcode_commons_status(&c.request, &c.reply);
    const char *cmd_status =
        json_get_str(json_get(&c.reply.data, "verification_status"));
    int64_t cmd_creations =
        json_get_int(json_get(&c.reply.data, "creation_objects"));
    int64_t cmd_epochs =
        json_get_int(json_get(&c.reply.data, "epoch_objects"));
    r = ms_get(dd, "/metaverse/commons", &len);
    char marker[96];
    snprintf(marker, sizeof(marker),
             "verification status</b><span class='val'>%s",
             cmd_status ? cmd_status : "(none)");
    MS_CHECK("agreement: commons status == commons page",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED && cmd_status &&
             cmd_creations == 0 && cmd_epochs == 0 &&
             strstr(r, marker) &&
             strstr(r, "creation objects</b><span class='val'>0</span>"));
    ms_cmd_free(&c);

    /* metaverse.space.show ↔ the space record behind the page. */
    ms_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "workspace", workspace);
    (void)json_push_kv_str(&c.input, "root", root_hex);
    zcl_native_handle_metaverse_space_show(&c.request, &c.reply);
    const char *cmd_protocol =
        json_get_str(json_get(&c.reply.data, "protocol_root"));
    const char *cmd_grade =
        json_get_str(json_get(&c.reply.data, "evidence_grade"));
    MS_CHECK("agreement: space show == committed descriptor",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             cmd_protocol && strlen(cmd_protocol) == 64 &&
             cmd_grade && strcmp(cmd_grade, "local_content_hash") == 0 &&
             strncmp(cmd_protocol, "4142434445464748494a4b4c4d4e4f50",
                     32) == 0);
    ms_cmd_free(&c);

    /* The landing page's descriptor count agrees with the space page. */
    r = ms_get(dd, "/metaverse", &len);
    MS_CHECK("agreement: landing counts the fixture descriptor",
             len > 0 &&
             strstr(r, "service descriptors</b><span class='val'>1</span>"));

    return failures;
}

/* ══ 3. empty projections ════════════════════════════════════════════ */

static int t_empty(const char *dd)
{
    int failures = 0;
    size_t len = 0;

    const char *r = ms_get(dd, "/metaverse/space", &len);
    MS_CHECK("empty: space page names the empty CAS",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "0 spaces") &&
             strstr(r, "No published spaces known locally"));

    r = ms_get(dd, "/metaverse/property", &len);
    MS_CHECK("empty: property page renders zero-property kinds",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "0 properties across") &&
             strstr(r, "No properties projected"));

    r = ms_get(dd, "/metaverse/commons", &len);
    MS_CHECK("empty: commons page unknown + zero",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "unknown") &&
             strstr(r, "minted atoms (simulated)</b>"
                       "<span class='val'>0</span>"));

    r = ms_get(dd, "/metaverse", &len);
    MS_CHECK("empty: landing still renders honestly",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "nobody owns the world they build in"));
    return failures;
}

/* ══ 4. honest failures + escaping ═══════════════════════════════════ */

static int t_failures(const char *dd)
{
    int failures = 0;
    size_t len = 0;

    const char *r = ms_get(dd, "/metaverse/property?kind=bogus", &len);
    MS_CHECK("failure: unknown kind is a named 400, not an unfiltered page",
             len > 0 && strstr(r, "HTTP/1.1 400") == r &&
             strstr(r, "unknown kind"));

    r = ms_get(dd, "/metaverse/nope-<script>", &len);
    MS_CHECK("failure: unknown route 404 escapes the path",
             len > 0 && strstr(r, "HTTP/1.1 404") == r &&
             strstr(r, "Unknown metaverse route") &&
             !strstr(r, "nope-<script>") &&
             strstr(r, "nope-&lt;script&gt;"));

    r = ms_get(dd, "/metaverse/property?kind=%3Cscript%3E", &len);
    MS_CHECK("failure: hostile kind filter is rejected, never reflected",
             len > 0 && strstr(r, "HTTP/1.1 400") == r &&
             !strstr(r, "<script>") && !strstr(r, "&lt;script&gt;"));
    return failures;
}

/* ══ 5. bounded output ═══════════════════════════════════════════════ */

static int t_bounded(const char *dd)
{
    int failures = 0;
    static const char *const routes[] = {
        "/metaverse", "/metaverse/property", "/metaverse/space",
        "/metaverse/commons",
    };
    bool all_fit = true;
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        size_t len = 0;
        const char *r = ms_get(dd, routes[i], &len);
        if (!(len > 0 && len < 65536 /* the onion budget */ &&
              strstr(r, "HTTP/1.1 200 OK") == r &&
              strstr(r, "</html>")))
            all_fit = false;
    }
    MS_CHECK("bounded: every page is complete and inside the onion budget",
             all_fit);
    return failures;
}

/* ══ group entry ═════════════════════════════════════════════════════ */

int test_metaverse_site(void)
{
    int failures = 0;
    printf("metaverse_site: starting\n");

    g_resp = malloc(MS_RESP_CAP);
    if (!g_resp) {
        printf("  metaverse_site: alloc... FAIL\n");
        return 1;
    }

    const char *dd = "./test-tmp/metaverse_site_main";
    test_rm_rf_recursive(dd);
    mkdir("./test-tmp", 0755);
    mkdir(dd, 0755);
    failures += t_routes_and_agreement(dd);
    failures += t_failures(dd);
    failures += t_bounded(dd);
    test_rm_rf_recursive(dd);

    const char *dd2 = "./test-tmp/metaverse_site_empty";
    test_rm_rf_recursive(dd2);
    mkdir(dd2, 0755);
    failures += t_empty(dd2);
    test_rm_rf_recursive(dd2);

    free(g_resp);
    g_resp = NULL;
    printf("metaverse_site: %s (%d failures)\n",
           failures == 0 ? "PASSED" : "FAILED", failures);
    return failures;
}
