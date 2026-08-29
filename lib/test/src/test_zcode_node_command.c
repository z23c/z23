/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_node_command — the `z23 join` / `z23 update` surface.
 *
 * Coverage:
 *   1. Registry contract: zcode.node.join is READY and binds the handler the
 *      direct cases below call; every zcode.node.update.* leaf is PLANNED with
 *      a NULL handler and a non-empty availability_reason, so it refuses BY
 *      NAME instead of silently doing nothing.
 *   2. `z23 join` and `z23 zcode node join` resolve to the SAME leaf, and
 *      `z23 update` resolves to zcode.node.update.status. An alias that
 *      resolves somewhere else is the whole failure mode this surface exists
 *      to avoid.
 *   3. THE BUDGETS. Adding a child to `zcode` is not free: the branch menu was
 *      2982 of its 3072 bytes before this lane, and an over-budget menu
 *      renders as NOTHING (write_bounded_json returns 0), not as a truncated
 *      menu. Root menu, the zcode menu, and the two new menus are all measured
 *      through the REAL renderer, and the root child count is pinned so a bare
 *      alias can never quietly become a 13th root.
 *   4. The handler on a temp datadir: it writes <datadir>/z23.conf with
 *      packagehost=1 and a buildworker line that AGREES with what it reported
 *      about the local compiler, preserves unrelated lines already in the
 *      file, is idempotent, and refuses a datadir that does not exist rather
 *      than minting one.
 *   5. Exactly ONE typed next command, taken through
 *      zcl_command_registry_execute_json so the registry's own hard
 *      validation of `next` (command_registry.c push_next_array) is the thing
 *      that accepts it — not this test's opinion.
 *   6. Both tiers are reported by name, with DHT marked optional. A join path
 *      that presents the fee-bearing on-chain anchor as a blocker would turn
 *      a free swarm join into a paid one.
 *   7. ReadConfigFile itself: the command line WINS over the file, `-datadir`
 *      inside the file is ignored, and the comment/bare-flag/leading-dash
 *      spellings all parse. Without this the join write is a file nobody
 *      reads.
 *   8. THE COMPOSED VERDICT. Reachability and speed must never collapse into
 *      one scalar: latency is telemetry beside the tuple, and this file
 *      proves that changing it moves NO dimension and NO readiness state. A
 *      timeout tuned on fast storage would otherwise grade a seek-bound but
 *      honest machine "fail", which is how a permissionless network quietly
 *      excludes the hardware it must admit.
 *   9. READY IS REACHABLE. `announcement.state` is `ready` only when all four
 *      stages are CONFIRMED — and an all-CONFIRMED readiness really does
 *      yield it. A gate whose passing condition can never be met is worse
 *      than no gate because it reports confidently; a mesh check requiring
 *      state=="active" read 0/4 for hours while onion P2P worked. Both halves
 *      are asserted: three-of-four is NOT ready and names the missing stage,
 *      four-of-four IS.
 *
 * No node is started, stopped, signalled or restarted anywhere in this file,
 * and every datadir is a fresh ./test-tmp directory. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_zcode_join.h"

#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define ZNJ_CHECK(name, expr) do {                                        \
    if (expr) { printf("  zcode_node: %s... OK\n", (name)); }             \
    else { printf("  zcode_node: %s... FAIL\n", (name)); failures++; }    \
} while (0)

static const struct zcl_command_spec *znt_leaf(const char *path)
{
    return zcl_command_registry_find(zcl_command_catalog(), path, NULL);
}

/* One invocation of a leaf through the same two steps the CLI takes:
 * input_validate first, then the bound handler. */
struct znt_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void znt_cmd_init(struct znt_cmd *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.zcode_node_test.v1");
}

static void znt_cmd_free(struct znt_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool znt_run(const struct zcl_command_spec *spec, struct znt_cmd *c,
                    char *why, size_t why_cap)
{
    if (!spec || !spec->handler)
        return false;
    if (!zcl_command_registry_input_validate(spec, &c->input, why, why_cap))
        return false;
    c->request.spec = spec;
    spec->handler(&c->request, &c->reply);
    return true;
}

/* Whole file as a NUL-terminated string, or NULL. */
static char *znt_slurp(const char *path)
{
    FILE *f = fopen(path, "re");
    if (!f)
        return NULL;
    char *buf = malloc(65536);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, 65535, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static bool znt_has_line(const char *text, const char *line)
{
    if (!text || !line)
        return false;
    size_t len = strlen(line);
    for (const char *p = text; p && *p;) {
        if (strncmp(p, line, len) == 0 && (p[len] == '\n' || p[len] == '\0'))
            return true;
        const char *nl = strchr(p, '\n');
        p = nl ? nl + 1 : NULL;
    }
    return false;
}

/* ── 1-2: the declarative contract and the aliases ──────────────────────── */

static int t_registry_contract(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();

    const struct zcl_command_spec *join = znt_leaf("zcode.node.join");
    ZNJ_CHECK("zcode.node.join is registered", join != NULL);
    ZNJ_CHECK("zcode.node.join is READY and binds the join handler",
              join && join->availability == ZCL_COMMAND_READY &&
              join->handler == zcl_native_handle_zcode_node_join);
    ZNJ_CHECK("zcode.node.join is a MUTATE leaf (it writes a config file)",
              join && join->effect == ZCL_COMMAND_EFFECT_MUTATE &&
              join->risk == ZCL_COMMAND_RISK_APP_WRITE);
    ZNJ_CHECK("zcode.node.join declares the datadir input it reads",
              join && join->input_keys &&
              strstr(join->input_keys, "datadir") != NULL);

    /* THE alias assertion: the bare root and the canonical path are one leaf.
     * find() returning two different specs would mean `z23 join` and
     * `z23 zcode node join` do different things. */
    bool was_alias = false;
    const struct zcl_command_spec *bare =
        zcl_command_registry_find(reg, "join", &was_alias);
    ZNJ_CHECK("`join` resolves, and resolves as an ALIAS",
              bare != NULL && was_alias);
    ZNJ_CHECK("`join` and `zcode.node.join` are the SAME leaf",
              bare != NULL && bare == join);
    ZNJ_CHECK("the native adapter owns the `join` root word",
              zcl_native_command_is_root("join"));

    const struct zcl_command_spec *status =
        znt_leaf("zcode.node.update.status");
    was_alias = false;
    const struct zcl_command_spec *bare_update =
        zcl_command_registry_find(reg, "update", &was_alias);
    ZNJ_CHECK("`update` resolves as an alias of zcode.node.update.status",
              status != NULL && bare_update == status && was_alias);
    ZNJ_CHECK("the native adapter owns the `update` root word",
              zcl_native_command_is_root("update"));

    /* Every update leaf must be PLANNED-with-a-reason. A READY leaf with no
     * implementation, or a PLANNED leaf with an empty reason, is the silent
     * stall this surface is explicitly designed not to be. */
    static const char *const planned[] = {
        "zcode.node.update.status",
        "zcode.node.update.check",
        "zcode.node.update.apply",
    };
    for (size_t i = 0; i < sizeof(planned) / sizeof(planned[0]); i++) {
        const struct zcl_command_spec *s = znt_leaf(planned[i]);
        char name[160];
        snprintf(name, sizeof(name), "%s is PLANNED, handler-free, and names "
                 "its reason", planned[i]);
        ZNJ_CHECK(name,
                  s && s->availability == ZCL_COMMAND_PLANNED &&
                  s->handler == NULL && s->availability_reason &&
                  s->availability_reason[0]);
    }
    return failures;
}

/* ── 3: the menu budgets this addition actually threatens ───────────────── */

static int t_menu_budgets(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_LIST_BUDGET + 1];

    size_t root_n = zcl_command_registry_menu_json(reg, "", out, sizeof(out));
    ZNJ_CHECK("the root menu still renders inside ZCL_COMMAND_ROOT_BUDGET",
              root_n > 0 && root_n <= ZCL_COMMAND_ROOT_BUDGET);

    /* An alias is not a child of "", so it must not appear at the root and
     * must not move the pinned root count (test_command_registry_catalog's
     * ASSERT_EQ(roots, 12) depends on exactly this). */
    ZNJ_CHECK("`join` and `update` do NOT render as root children",
              root_n > 0 && strstr(out, "\"join\"") == NULL &&
              strstr(out, "\"update\"") == NULL);
    size_t roots = 0;
    for (size_t i = 0; i < reg->count; i++) {
        const char *p = reg->commands[i].parent;
        if (!p || !p[0])
            roots++;
    }
    ZNJ_CHECK("the registry still has exactly 12 roots", roots == 12);

    static const char *const branches[] = { "zcode", "zcode.node",
                                            "zcode.node.update" };
    for (size_t i = 0; i < sizeof(branches) / sizeof(branches[0]); i++) {
        size_t n = zcl_command_registry_menu_json(reg, branches[i], out,
                                                  sizeof(out));
        char name[160];
        snprintf(name, sizeof(name),
                 "%s renders (non-empty) inside ZCL_COMMAND_BRANCH_BUDGET",
                 branches[i]);
        ZNJ_CHECK(name, n > 0 && n <= ZCL_COMMAND_BRANCH_BUDGET);
    }

    size_t zcode_n = zcl_command_registry_menu_json(reg, "zcode", out,
                                                    sizeof(out));
    ZNJ_CHECK("the zcode menu lists the new node branch",
              zcode_n > 0 && strstr(out, "\"zcode.node\"") != NULL);
    return failures;
}

/* ── 4-6: the handler ───────────────────────────────────────────────────── */

static int t_join_writes_config(void)
{
    int failures = 0;
    const struct zcl_command_spec *join = znt_leaf("zcode.node.join");
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_node", "join");

    /* An unrelated setting already in the file must survive the rewrite: the
     * command owns two flags, not the operator's whole configuration. */
    char conf[512];
    snprintf(conf, sizeof(conf), "%s/z23.conf", dd);
    FILE *seed = fopen(conf, "we");
    if (seed) {
        fputs("# operator note\ntxindex=1\n", seed);
        fclose(seed);
    }

    char why[192] = {0};
    struct znt_cmd c;
    znt_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    bool ran = znt_run(join, &c, why, sizeof(why));
    ZNJ_CHECK("join runs through input_validate and the bound handler", ran);
    if (!ran)
        printf("    validator refused: %s\n", why);
    ZNJ_CHECK("join passes", ran && c.reply.status == ZCL_COMMAND_STATUS_PASSED);

    const char *reported_conf =
        json_get_str(json_get(&c.reply.data, "config_file"));
    ZNJ_CHECK("join reports the config file it wrote",
              reported_conf && strcmp(reported_conf, conf) == 0);

    bool compiler_present =
        json_get_bool(json_get(&c.reply.data, "compiler_present"));
    const char *wrote = json_get_str(json_get(&c.reply.data, "wrote_flags"));
    ZNJ_CHECK("join names the exact flags it wrote", wrote && wrote[0]);

    char *text = znt_slurp(conf);
    ZNJ_CHECK("the config file exists after join", text != NULL);
    ZNJ_CHECK("packagehost=1 is written unconditionally",
              znt_has_line(text, "packagehost=1"));
    /* This group only runs after the tree compiled as C23, so a working
     * driver is on PATH. Probing `/dev/null` with -pedantic-errors rejects
     * an empty translation unit and used to report compiler_present=false
     * / buildworker=0 on exactly those hosts — advertising no compile
     * capacity the box can deliver. The handler itself is the detector. */
    ZNJ_CHECK("join reports compiler_present on a host that built this C23 tree",
              compiler_present);
    ZNJ_CHECK("join writes buildworker=1 rather than a false empty-TU 0",
              znt_has_line(text, "buildworker=1"));
    /* The file is the swarm-tier fact. `joined` stays this process's flags
     * and must not be inverted just because the write succeeded. */
    ZNJ_CHECK("swarm_member is true once packagehost=1 is written",
              json_get_bool(json_get(&c.reply.data, "swarm_member")));
    ZNJ_CHECK("config_package_hosting reflects the written file",
              json_get_bool(json_get(&c.reply.data,
                                     "config_package_hosting")));
    ZNJ_CHECK("config_build_worker agrees with the compiler probe",
              json_get_bool(json_get(&c.reply.data, "config_build_worker"))
                  == compiler_present);
    ZNJ_CHECK("joined stays this process's flags, not the file just written",
              json_get_str(json_get(&c.reply.data, "swarm_member_means"))
                  && strstr(json_get_str(json_get(&c.reply.data,
                                                  "swarm_member_means")),
                            "this process") != NULL);
    {
        static const char probe_prefix[] = ".z23-join-c23-probe.";
        bool probe_left = false;
        DIR *dir = opendir(dd);
        struct dirent *entry = NULL;
        while (dir && (entry = readdir(dir)) != NULL)
            if (strncmp(entry->d_name, probe_prefix,
                        sizeof(probe_prefix) - 1) == 0)
                probe_left = true;
        if (dir)
            closedir(dir);
        ZNJ_CHECK("the private C23 probe source is removed", !probe_left);
    }
    /* The one claim that must never drift: what the reply SAYS about the
     * compiler and what the file DOES about the worker are the same fact. */
    ZNJ_CHECK("buildworker agrees with the reported compiler",
              compiler_present ? znt_has_line(text, "buildworker=1")
                               : znt_has_line(text, "buildworker=0"));
    ZNJ_CHECK("an unrelated pre-existing setting survives the rewrite",
              znt_has_line(text, "txindex=1"));
    ZNJ_CHECK("the flags land exactly once each",
              text && !strstr(text, "packagehost=1\npackagehost=1"));
    ZNJ_CHECK("join reports the first write as a change",
              json_get_bool(json_get(&c.reply.data, "config_changed")));

    /* Tiers, by name. DHT optional is the load-bearing bit. */
    const struct json_value *swarm = json_get(&c.reply.data, "swarm_tier");
    const struct json_value *dht = json_get(&c.reply.data, "dht_tier");
    ZNJ_CHECK("the SWARM tier is reported and needs only -packagehost=1",
              swarm && json_get_str(json_get(swarm, "requires")) &&
              strstr(json_get_str(json_get(swarm, "requires")),
                     "-packagehost=1") != NULL &&
              json_get_bool(json_get(swarm, "optional")) == false);
    ZNJ_CHECK("the DHT tier is reported as an OPTIONAL upgrade, not a blocker",
              dht && json_get_bool(json_get(dht, "optional")));
    ZNJ_CHECK("the DHT tier names -noisetransport and the fee-bearing anchor",
              dht && json_get_str(json_get(dht, "requires")) &&
              strstr(json_get_str(json_get(dht, "requires")),
                     "-noisetransport") != NULL &&
              strstr(json_get_str(json_get(dht, "requires")), "fee") != NULL);
    ZNJ_CHECK("join names a restart instead of performing one",
              json_get_bool(json_get(&c.reply.data, "restart_required")) &&
              json_get_str(json_get(&c.reply.data, "restart_command")) &&
              strcmp(json_get_str(json_get(&c.reply.data, "restart_command")),
                     "systemctl --user restart zclassic23") == 0);

    /* The composed verdict, as the join reply actually emits it. */
    const struct json_value *verdict = json_get(&c.reply.data, "verdict");
    const struct json_value *announce =
        json_get(&c.reply.data, "announcement");
    ZNJ_CHECK("join reports all four dimensions independently",
              verdict && json_get_str(json_get(verdict, "reachable")) &&
              json_get_str(json_get(verdict, "responsive")) &&
              json_get_str(json_get(verdict, "fresh")) &&
              json_get_str(json_get(verdict, "serving")));
    /* From a one-shot CLI these are structurally invisible. Reporting them as
     * `failed` would grade a healthy node broken for standing in the wrong
     * place; reporting them as `confirmed` would be a promise this process
     * cannot keep. */
    ZNJ_CHECK("join reports what it cannot see as unobservable, not failed",
              verdict &&
              strcmp(json_get_str(json_get(verdict, "reachable")),
                     "unobservable") == 0 &&
              strcmp(json_get_str(json_get(verdict, "serving")),
                     "unobservable") == 0);
    ZNJ_CHECK("join names the vantage that CAN answer those dimensions",
              verdict && json_get_str(json_get(verdict, "vantage")) &&
              json_get_str(json_get(verdict, "vantage"))[0]);
    ZNJ_CHECK("join reports latency as unmeasured rather than inventing one",
              verdict && json_get_int(json_get(verdict, "latency_ms")) < 0);
    ZNJ_CHECK("join never announces ready from a vantage that cannot see it",
              announce && strcmp(json_get_str(json_get(announce, "state")),
                                 "ready") != 0);
    ZNJ_CHECK("join marks the outstanding stage unobservable, not in-progress",
              announce &&
              strcmp(json_get_str(json_get(announce, "state_signal")),
                     "unobservable") == 0);
    ZNJ_CHECK("join names the four announcement stages separately",
              announce &&
              json_get_str(json_get(announce, "descriptor_published")) &&
              json_get_str(json_get(announce, "rendezvous_established")) &&
              json_get_str(json_get(announce, "circuit_built")) &&
              json_get_str(json_get(announce, "listener_accepting")));
    ZNJ_CHECK("join says the joined scalar is config, not a reachability verdict",
              json_get_str(json_get(&c.reply.data, "joined_means")) != NULL);

    /* The typed next command, counted and validated by the registry itself. */
    ZNJ_CHECK("join emits exactly one typed next command",
              c.reply.next_count == 1);
    ZNJ_CHECK("the next command verifies resident Commons service",
              c.reply.next_count == 1 &&
              strcmp(c.reply.next[0].command, "zcode.package.offered") == 0);
    ZNJ_CHECK("the next command names the datadir join just wrote",
              c.reply.next_count == 1 &&
              strstr(c.reply.next[0].input_json, dd) != NULL);
    free(text);
    znt_cmd_free(&c);

    /* Re-running must be idempotent: same two lines, and now reported as no
     * change, because a node that is already joined must not be told to
     * restart again. */
    znt_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    bool again = znt_run(join, &c, why, sizeof(why));
    ZNJ_CHECK("join re-runs cleanly",
              again && c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    ZNJ_CHECK("the second run reports no flag change",
              again && !json_get_bool(json_get(&c.reply.data,
                                               "config_changed")));
    text = znt_slurp(conf);
    ZNJ_CHECK("the second run still leaves exactly one packagehost line",
              text && !strstr(text, "packagehost=1\npackagehost=1"));
    ZNJ_CHECK("the second run still preserves the unrelated setting",
              znt_has_line(text, "txindex=1"));
    free(text);
    znt_cmd_free(&c);

    /* A flag whose VALUE flipped is a change, even though its key was
     * present both times. Deciding "changed" from key presence alone
     * reported "no change" for a node that had joined on a box with no C23
     * compiler and later gained one: buildworker really did go 0 -> 1, the
     * node's behaviour really did depend on a restart, and the operator was
     * told there was nothing to do.
     *
     * The expected value is read from the run above rather than assumed, so
     * this asserts the same thing on a build host with a compiler and one
     * without. */
    {
        znt_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", dd);
        bool probe = znt_run(join, &c, why, sizeof(why));
        bool decided = probe && json_get_bool(json_get(&c.reply.data,
                                                       "compiler_present"));
        znt_cmd_free(&c);

        FILE *seed = fopen(conf, "we");
        if (seed) {
            fprintf(seed, "packagehost=1\nbuildworker=%d\ntxindex=1\n",
                    decided ? 0 : 1);
            fclose(seed);
        }
        znt_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", dd);
        bool flip = znt_run(join, &c, why, sizeof(why));
        ZNJ_CHECK("a buildworker value that flipped IS reported as a change",
                  seed && flip &&
                  json_get_bool(json_get(&c.reply.data, "config_changed")));
        text = znt_slurp(conf);
        ZNJ_CHECK("the flipped run writes the decided value and keeps the "
                  "operator's unrelated setting",
                  text && znt_has_line(text, "txindex=1") &&
                  znt_has_line(text, decided ? "buildworker=1"
                                             : "buildworker=0"));
        free(text);
        znt_cmd_free(&c);

        /* The negated spelling is a VALUE (off), not an occurrence of the
         * flag being on, so against a decided buildworker=1 it must compare
         * as different rather than as already-on. */
        if (decided) {
            seed = fopen(conf, "we");
            if (seed) {
                fprintf(seed, "packagehost=1\n-nobuildworker\n");
                fclose(seed);
            }
            znt_cmd_init(&c);
            (void)json_push_kv_str(&c.input, "datadir", dd);
            bool neg = znt_run(join, &c, why, sizeof(why));
            ZNJ_CHECK("a negated -nobuildworker line reads as off, not as "
                      "already-on",
                      seed && neg &&
                      json_get_bool(json_get(&c.reply.data,
                                             "config_changed")));
            znt_cmd_free(&c);
        }
    }

    unlink(conf);
    test_cleanup_tmpdir(dd);
    return failures;
}

static int t_join_refuses_missing_datadir(void)
{
    int failures = 0;
    const struct zcl_command_spec *join = znt_leaf("zcode.node.join");
    char why[192] = {0};
    struct znt_cmd c;
    znt_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir",
                           "./test-tmp/zcode_node_absent_dir");
    bool ran = znt_run(join, &c, why, sizeof(why));
    ZNJ_CHECK("join accepts the input but refuses a datadir that is not there",
              ran && c.reply.status == ZCL_COMMAND_STATUS_FAILED);
    ZNJ_CHECK("the refusal is named DATADIR_MISSING (no directory is minted)",
              ran && strcmp(c.reply.error.code, "DATADIR_MISSING") == 0);
    struct stat st;
    ZNJ_CHECK("the named datadir still does not exist",
              stat("./test-tmp/zcode_node_absent_dir", &st) != 0);
    znt_cmd_free(&c);
    return failures;
}

/* 5, through the real envelope: push_next_array re-resolves every `next`
 * against the registry and refuses the whole document if one does not
 * validate, so a passing envelope IS the proof the next command is real. */
static int t_join_envelope_next_is_registry_validated(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *join = znt_leaf("zcode.node.join");
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_node", "envelope");

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dd);

    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = zcl_command_registry_execute_json(
        reg, join, NULL, &input, /*invoked_by_alias=*/true, "join",
        NULL, 0, 0, NULL, out, sizeof(out), &code);
    ZNJ_CHECK("the join envelope renders inside the result budget",
              n > 0 && n <= ZCL_COMMAND_RESULT_BUDGET);
    ZNJ_CHECK("the join envelope is ok and exits 0",
              n > 0 && code == ZCL_COMMAND_EXIT_OK &&
              strstr(out, "\"ok\":true") != NULL);
    ZNJ_CHECK("the rendered envelope carries the typed next command",
              n > 0 && strstr(out, "zcode.package.offered") != NULL);

    struct json_value doc;
    json_init(&doc);
    bool parsed = n > 0 && json_read(&doc, out, n) && doc.type == JSON_OBJ;
    const struct json_value *next = parsed ? json_get(&doc, "next") : NULL;
    ZNJ_CHECK("exactly one next entry survives registry validation",
              next && next->type == JSON_ARR && next->num_children == 1);
    {
        const struct json_value *n0 =
            next && next->type == JSON_ARR && next->num_children == 1
                ? json_at(next, 0) : NULL;
        const char *next_dd =
            json_get_str(json_get(json_get(n0, "input"), "datadir"));
        ZNJ_CHECK("the envelope next input is the same datadir",
                  next_dd && strcmp(next_dd, dd) == 0);
    }
    json_free(&doc);
    json_free(&input);

    char conf[512];
    snprintf(conf, sizeof(conf), "%s/z23.conf", dd);
    unlink(conf);
    test_cleanup_tmpdir(dd);
    return failures;
}

/* Every update leaf refuses BY NAME through the real dispatcher. */
static int t_update_leaves_refuse_by_name(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    static const char *const paths[] = {
        "zcode.node.update.status",
        "zcode.node.update.check",
        "zcode.node.update.apply",
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        const struct zcl_command_spec *s = znt_leaf(paths[i]);
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        char out[ZCL_COMMAND_ERROR_BUDGET + 1];
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_OK;
        size_t n = s ? zcl_command_registry_execute_json(
                           reg, s, NULL, &input, false, paths[i], NULL, 0, 0,
                           NULL, out, sizeof(out), &code)
                     : 0;
        char name[192];
        snprintf(name, sizeof(name),
                 "%s blocks with a typed COMMAND_PLANNED refusal", paths[i]);
        ZNJ_CHECK(name,
                  n > 0 && code == ZCL_COMMAND_EXIT_BLOCKED &&
                  strstr(out, "\"ok\":false") != NULL &&
                  strstr(out, "COMMAND_PLANNED") != NULL);
        json_free(&input);
    }
    return failures;
}


/* ── 8-9: the composed verdict type ─────────────────────────────────────── */

static int t_verdict_composes(void)
{
    int failures = 0;

    /* A zero-initialized verdict must claim NOTHING. If the default were
     * "confirmed" every uninitialized struct in the tree would announce a
     * promise it cannot keep. */
    struct zcl_join_verdict zero = {0};
    ZNJ_CHECK("an unfilled verdict claims nothing",
              zero.reachable == ZCL_JOIN_SIGNAL_UNCONFIRMED &&
              zero.responsive == ZCL_JOIN_SIGNAL_UNCONFIRMED &&
              zero.fresh == ZCL_JOIN_SIGNAL_UNCONFIRMED &&
              zero.serving == ZCL_JOIN_SIGNAL_UNCONFIRMED);
    ZNJ_CHECK("each signal has a distinct name",
              strcmp(zcl_join_signal_name(ZCL_JOIN_SIGNAL_CONFIRMED),
                     "confirmed") == 0 &&
              strcmp(zcl_join_signal_name(ZCL_JOIN_SIGNAL_UNCONFIRMED),
                     "unconfirmed") == 0 &&
              strcmp(zcl_join_signal_name(ZCL_JOIN_SIGNAL_FAILED),
                     "failed") == 0 &&
              strcmp(zcl_join_signal_name(ZCL_JOIN_SIGNAL_UNOBSERVABLE),
                     "unobservable") == 0);

    /* THE non-collapse property. `reachable + slow + fresh` must stay exactly
     * that: the same four dimensions whatever the clock says. Two verdicts
     * that differ ONLY in latency must render identical dimension rows. */
    struct zcl_join_verdict fast = {
        .reachable = ZCL_JOIN_SIGNAL_CONFIRMED,
        .responsive = ZCL_JOIN_SIGNAL_CONFIRMED,
        .fresh = ZCL_JOIN_SIGNAL_CONFIRMED,
        .serving = ZCL_JOIN_SIGNAL_CONFIRMED,
        .latency_ms = 3, .data_age_s = 1, .vantage = "t",
    };
    struct zcl_join_verdict slow = fast;
    slow.latency_ms = 900000;      /* a seek-bound box under IO pressure */
    slow.data_age_s = 1;

    struct json_value a, b;
    json_init(&a);
    json_init(&b);
    json_set_object(&a);
    json_set_object(&b);
    ZNJ_CHECK("both verdicts render",
              zcl_join_verdict_push_json(&a, &fast, NULL) &&
              zcl_join_verdict_push_json(&b, &slow, NULL));
    const struct json_value *va = json_get(&a, "verdict");
    const struct json_value *vb = json_get(&b, "verdict");
    bool same_dims =
        va && vb &&
        strcmp(json_get_str(json_get(va, "reachable")),
               json_get_str(json_get(vb, "reachable"))) == 0 &&
        strcmp(json_get_str(json_get(va, "responsive")),
               json_get_str(json_get(vb, "responsive"))) == 0 &&
        strcmp(json_get_str(json_get(va, "fresh")),
               json_get_str(json_get(vb, "fresh"))) == 0 &&
        strcmp(json_get_str(json_get(va, "serving")),
               json_get_str(json_get(vb, "serving"))) == 0;
    ZNJ_CHECK("a 900-second latency changes NO dimension", same_dims);
    ZNJ_CHECK("speed is still reported, as its own measured number",
              vb && json_get_int(json_get(vb, "latency_ms")) == 900000);
    ZNJ_CHECK("the reply says out loud that speed is not a gate input",
              vb && json_get_bool(json_get(vb,
                                           "speed_is_telemetry_not_a_gate")));
    /* "reachable + slow + fresh" must be expressible and must not read as a
     * failure anywhere in the tuple. */
    ZNJ_CHECK("a reachable-but-slow node is not graded failed",
              vb && strcmp(json_get_str(json_get(vb, "reachable")),
                           "confirmed") == 0 &&
              strcmp(json_get_str(json_get(vb, "fresh")), "confirmed") == 0);
    json_free(&a);
    json_free(&b);

    /* Not-measured must be distinguishable from fast. */
    struct zcl_join_verdict unmeasured = {0};
    unmeasured.latency_ms = -1;
    json_init(&a);
    json_set_object(&a);
    (void)zcl_join_verdict_push_json(&a, &unmeasured, NULL);
    ZNJ_CHECK("an unmeasured latency is negative, never 0",
              json_get_int(json_get(json_get(&a, "verdict"), "latency_ms"))
                  == -1);
    json_free(&a);
    return failures;
}

static int t_ready_is_a_promise_and_is_reachable(void)
{
    int failures = 0;

    /* THE reachability proof. A passing condition that cannot be met is worse
     * than no check at all — it reports confidently and is believed. */
    struct zcl_join_readiness all = {
        .descriptor_published = ZCL_JOIN_SIGNAL_CONFIRMED,
        .rendezvous_established = ZCL_JOIN_SIGNAL_CONFIRMED,
        .circuit_built = ZCL_JOIN_SIGNAL_CONFIRMED,
        .listener_accepting = ZCL_JOIN_SIGNAL_CONFIRMED,
    };
    ZNJ_CHECK("all four confirmed REALLY does reach ready",
              strcmp(zcl_join_readiness_state(&all), "ready") == 0);

    /* Three of four is never ready, and the state NAMES the outstanding
     * stage, so "still building circuits" is reportable instead of a silent
     * not-ready. */
    struct zcl_join_readiness r = all;
    r.listener_accepting = ZCL_JOIN_SIGNAL_UNCONFIRMED;
    ZNJ_CHECK("three of four is not ready, and names the last stage",
              strcmp(zcl_join_readiness_state(&r), "opening-listener") == 0);
    r = all;
    r.circuit_built = ZCL_JOIN_SIGNAL_UNCONFIRMED;
    ZNJ_CHECK("a missing circuit reports building-circuit",
              strcmp(zcl_join_readiness_state(&r), "building-circuit") == 0);
    r = all;
    r.rendezvous_established = ZCL_JOIN_SIGNAL_UNCONFIRMED;
    ZNJ_CHECK("a missing rendezvous reports establishing-rendezvous",
              strcmp(zcl_join_readiness_state(&r),
                     "establishing-rendezvous") == 0);
    r = all;
    r.descriptor_published = ZCL_JOIN_SIGNAL_UNCONFIRMED;
    ZNJ_CHECK("a missing descriptor reports publishing-descriptor",
              strcmp(zcl_join_readiness_state(&r),
                     "publishing-descriptor") == 0);

    /* UNOBSERVABLE is not a quiet synonym for CONFIRMED. */
    r = all;
    r.circuit_built = ZCL_JOIN_SIGNAL_UNOBSERVABLE;
    ZNJ_CHECK("an UNOBSERVABLE stage never advances the promise",
              strcmp(zcl_join_readiness_state(&r), "building-circuit") == 0);
    r = all;
    r.listener_accepting = ZCL_JOIN_SIGNAL_FAILED;
    ZNJ_CHECK("a FAILED stage never advances the promise",
              strcmp(zcl_join_readiness_state(&r), "opening-listener") == 0);

    struct zcl_join_readiness none = {0};
    ZNJ_CHECK("a zero-initialized readiness is the FIRST stage, not ready",
              strcmp(zcl_join_readiness_state(&none),
                     "publishing-descriptor") == 0);
    ZNJ_CHECK("a NULL readiness is the first stage, never ready",
              strcmp(zcl_join_readiness_state(NULL),
                     "publishing-descriptor") == 0);

    /* A stage NAME alone reads like progress. The companion signal keeps
     * "we cannot see it" apart from "it is underway" and from "it failed". */
    ZNJ_CHECK("all confirmed reports the outstanding signal as confirmed",
              zcl_join_readiness_outstanding(&all) ==
                  ZCL_JOIN_SIGNAL_CONFIRMED);
    r = all;
    r.circuit_built = ZCL_JOIN_SIGNAL_UNOBSERVABLE;
    ZNJ_CHECK("an unobservable stage says unobservable, not in-progress",
              zcl_join_readiness_outstanding(&r) ==
                  ZCL_JOIN_SIGNAL_UNOBSERVABLE &&
              strcmp(zcl_join_readiness_state(&r), "building-circuit") == 0);
    r.circuit_built = ZCL_JOIN_SIGNAL_FAILED;
    ZNJ_CHECK("a failed stage says failed, on the same stage name",
              zcl_join_readiness_outstanding(&r) == ZCL_JOIN_SIGNAL_FAILED &&
              strcmp(zcl_join_readiness_state(&r), "building-circuit") == 0);

    /* Latency must not reach the promise either. */
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    struct zcl_join_verdict crawling = {
        .reachable = ZCL_JOIN_SIGNAL_CONFIRMED, .latency_ms = 1800000,
        .data_age_s = 4, .vantage = "t",
    };
    (void)zcl_join_verdict_push_json(&doc, &crawling, &all);
    ZNJ_CHECK("a 30-minute latency does not withdraw a fully confirmed ready",
              strcmp(json_get_str(json_get(json_get(&doc, "announcement"),
                                           "state")), "ready") == 0);
    json_free(&doc);
    return failures;
}

/* ── 7: the reader that makes the written file mean anything ────────────── */

static int t_config_file_reader(void)
{
    int failures = 0;
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_node", "conf");
    char conf[512];
    snprintf(conf, sizeof(conf), "%s/z23.conf", dd);

    FILE *f = fopen(conf, "we");
    if (f) {
        fputs("# a comment\n"
              "\n"
              "packagehost=1\n"
              "-buildworker=1\n"
              "txindex\n"
              "  spaced = 7 \n"
              "datadir=/somewhere/else\n",
              f);
        fclose(f);
    }

    /* argv sets -packagehost=0 explicitly; the file must NOT overturn it. */
    const char *argv[] = { "z23", "-packagehost=0" };
    ParseParameters(2, argv);
    int applied = ReadConfigFile(conf);
    ZNJ_CHECK("ReadConfigFile reports the settings it applied", applied >= 3);
    ZNJ_CHECK("the COMMAND LINE wins over the config file",
              GetBoolArg("-packagehost", true) == false);
    ZNJ_CHECK("a key argv did not mention is filled from the file",
              GetBoolArg("-buildworker", false) == true);
    ZNJ_CHECK("a bare flag line means true",
              GetBoolArg("-txindex", false) == true);
    ZNJ_CHECK("whitespace around the key and value is trimmed",
              strcmp(GetArg("-spaced", ""), "7") == 0);
    /* The file lives INSIDE the datadir, so a datadir key in it could
     * relocate the directory it was just read from. It is ignored. */
    ZNJ_CHECK("a -datadir inside the config file is ignored",
              strcmp(GetArg("-datadir", ""), "") == 0);

    ZNJ_CHECK("a missing config file is not an error and changes nothing",
              ReadConfigFile("./test-tmp/zcode_node_no_such.conf") == -1);

    /* GetConfigFilePath must derive from -datadir without creating anything. */
    const char *argv2[] = { "z23", "-datadir=./test-tmp/zcode_node_nodir" };
    ParseParameters(2, argv2);
    char path[4600];
    GetConfigFilePath(NULL, path, sizeof(path));
    ZNJ_CHECK("GetConfigFilePath derives <datadir>/z23.conf",
              strcmp(path, "./test-tmp/zcode_node_nodir/z23.conf") == 0);
    struct stat st;
    ZNJ_CHECK("GetConfigFilePath creates no directory",
              stat("./test-tmp/zcode_node_nodir", &st) != 0);
    GetConfigFilePath("./test-tmp/zcode_node_explicit", path, sizeof(path));
    ZNJ_CHECK("an explicit datadir beats the argument table",
              strcmp(path, "./test-tmp/zcode_node_explicit/z23.conf") == 0);

    /* THE regression this scan exists for: ParseParameters stops at the first
     * non-'-' token, so for a real CLI argv the table is EMPTY and only a
     * whole-argv scan finds the datadir the operator named. Reading the table
     * instead would silently target their live node. */
    const char *cli_argv[] = { "z23", "zcode", "work", "toolchain",
                               "-datadir=/tmp/znt-cli" };
    ParseParameters(5, cli_argv);
    ZNJ_CHECK("ParseParameters really does stop at the first non-flag token",
              strcmp(GetArg("-datadir", ""), "") == 0);
    char scanned[4096];
    ZNJ_CHECK("ArgvDataDir finds -datadir anywhere in argv",
              ArgvDataDir(5, cli_argv, scanned, sizeof(scanned)) &&
              strcmp(scanned, "/tmp/znt-cli") == 0);
    const char *no_dd[] = { "z23", "status" };
    ZNJ_CHECK("ArgvDataDir reports absence rather than guessing",
              !ArgvDataDir(2, no_dd, scanned, sizeof(scanned)) &&
              scanned[0] == '\0');

    /* Leave the process-wide argument table as this group found it. */
    const char *reset[] = { "z23" };
    ParseParameters(1, reset);

    unlink(conf);
    test_cleanup_tmpdir(dd);
    return failures;
}

int test_zcode_node_command(void)
{
    int failures = 0;
    printf("=== zcode_node_command ===\n");
    failures += t_registry_contract();
    failures += t_menu_budgets();
    failures += t_join_writes_config();
    failures += t_join_refuses_missing_datadir();
    failures += t_join_envelope_next_is_registry_validated();
    failures += t_verdict_composes();
    failures += t_ready_is_a_promise_and_is_reachable();
    failures += t_update_leaves_refuse_by_name();
    failures += t_config_file_reader();
    printf("=== zcode_node_command: %d failures ===\n", failures);
    return failures;
}
