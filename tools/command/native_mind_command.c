/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `dev mind ask|status|serve` — the CLI half of the per-node mind.
 *
 * ASK never rebuilds and never serves a stale answer. Those are the same
 * rule seen from two sides: the resident owns the rebuild, so a query that
 * rebuilt would be a second writer, and an answer from a generation the
 * source tree has moved past is wrong in a way the caller cannot see. Both
 * end in the typed refusal `INDEX_STALE`, which carries the index root, that
 * generation's age, and the owner's last heartbeat so the caller knows
 * whether to wait for a resident or start one.
 *
 * Bound by engine/composition/commands/mind.def.
 */

#include "command/native_command.h"

#include "codeindex/codeindex.h"
#include "controllers/agent_impact_rules.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "mind.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The closed question vocabulary. An unknown kind is refused by name rather
 * than answered generically: a mind that guesses what it was asked is worse
 * than one that says it does not know the question. */
static const char *const g_mind_kinds[] = {
    "where_is", "owns", "tests_for", "executor_for", "next_passage",
    "trap_of",
};

static const char *mind_str(const struct zcl_command_request *request,
                            const char *key)
{
    const char *v = json_get_str(json_get(request->input, key));
    return (v && v[0]) ? v : NULL;
}

static bool mind_flag(const struct zcl_command_request *request,
                      const char *key)
{
    const struct json_value *v = json_get(request->input, key);
    if (!v) return false;
    if (v->type == JSON_BOOL) return json_get_bool(v);
    const char *s = v->type == JSON_STR ? json_get_str(v) : NULL;
    return s && (strcmp(s, "true") == 0 || strcmp(s, "1") == 0);
}

static const char *mind_source_root(const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
    return env && env[0] ? env : ".";
}

static void mind_push_str(struct json_value *arr, const char *s)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, s ? s : "");
    (void)json_push_back(arr, &item);
    json_free(&item);
}

/* One row of an answer: what was found, where, and what kind of thing it is.
 * Rows are uniform across question kinds on purpose — a caller renders the
 * table once. */
static void mind_push_row(struct json_value *arr, const char *what,
                          const char *where, int line, const char *detail)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "what", what ? what : "");
    (void)json_push_kv_str(&row, "where", where ? where : "");
    (void)json_push_kv_int(&row, "line", line);
    (void)json_push_kv_str(&row, "detail", detail ? detail : "");
    (void)json_push_back(arr, &row);
    json_free(&row);
}

/* The refusal. It is deliberately loud about which of the two reasons applies
 * — an owner is working, or nobody is — because the next action differs. */
static void mind_refuse_stale(struct zcl_command_reply *reply,
                              const char *root, long long age_s,
                              const char *index_root)
{
    long long owner_pid = 0, owner_beat = 0;
    bool owned = codeindex_owner_read(root, &owner_pid, &owner_beat);
    long long now = (long long)platform_time_wall_time_t();
    char evidence[512];
    if (owned)
        (void)snprintf(evidence, sizeof(evidence),
                       "index_root=%s index_age_s=%lld owner_pid=%lld "
                       "owner_heartbeat_age_s=%lld root=%s",
                       index_root[0] ? index_root : "unsealed", age_s,
                       owner_pid, now - owner_beat, root);
    else
        (void)snprintf(evidence, sizeof(evidence),
                       "index_root=%s index_age_s=%lld owner=none root=%s",
                       index_root[0] ? index_root : "unsealed", age_s, root);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
        "INDEX_STALE", "dispatch", true, false,
        owned ? "the index for this checkout is behind the source tree and "
                "its owning mind is rebuilding it. This command never "
                "rebuilds and never answers from a superseded generation; "
                "ask again once the mind publishes."
              : "the index for this checkout is behind the source tree and "
                "no mind owns it. Start one with `z23 dev mind serve` (or "
                "the zcl-mind user unit) so exactly one process rebuilds it.",
        evidence);
    (void)zcl_command_reply_add_next(reply, "dev.mind.status", "{}",
                                     "see whether a mind is running here");
}

/* Hex of the generation this handle reads, or "" when the store carries no
 * sealed root. Never a zeroed root presented as an identity. */
static void mind_index_root(struct codeindex *ci, char out[65])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t root[32];
    out[0] = '\0';
    if (!ci || !codeindex_source_root_sha3(ci, root))
        return;
    for (size_t i = 0; i < sizeof(root); i++) {
        out[i * 2] = hex[root[i] >> 4];
        out[i * 2 + 1] = hex[root[i] & 0x0f];
    }
    out[64] = '\0';
}

/* ── the six questions ────────────────────────────────────────────────── */

static void mind_answer_where_is(struct codeindex *ci, const char *subject,
                                 struct json_value *rows, char *summary,
                                 size_t cap)
{
    struct ci_symbol sym;
    bool found = false;
    if (codeindex_symbol(ci, subject, &sym, &found) && found) {
        mind_push_row(rows, sym.name, sym.def_path[0] ? sym.def_path
                                                      : sym.decl_path,
                      sym.def_path[0] ? sym.def_line : sym.decl_line,
                      sym.signature);
        (void)snprintf(summary, cap, "%s is defined at %s:%d", sym.name,
                       sym.def_path[0] ? sym.def_path : sym.decl_path,
                       sym.def_path[0] ? sym.def_line : sym.decl_line);
        return;
    }
    struct ci_symbol hits[8];
    int n = codeindex_find(ci, subject, hits, 8);
    for (int i = 0; i < n; i++)
        mind_push_row(rows, hits[i].name,
                      hits[i].def_path[0] ? hits[i].def_path
                                          : hits[i].decl_path,
                      hits[i].def_path[0] ? hits[i].def_line
                                          : hits[i].decl_line,
                      hits[i].signature);
    if (n > 0)
        (void)snprintf(summary, cap,
                       "no exact symbol '%s'; %d near name(s) — the first is "
                       "%s at %s:%d", subject, n, hits[0].name,
                       hits[0].def_path[0] ? hits[0].def_path
                                           : hits[0].decl_path,
                       hits[0].def_path[0] ? hits[0].def_line
                                           : hits[0].decl_line);
    else
        (void)snprintf(summary, cap,
                       "the index holds no symbol matching '%s'. That is a "
                       "statement about the indexed names, not about the "
                       "tree", subject);
}

/* Ownership as the INDEX knows it: the group a file or a symbol's defining
 * file belongs to. The full territory scorecard — routed groups, reach,
 * dependants — is `code territory`, which costs seconds; this answers the
 * question a caller usually has, in the time a caller usually has. */
static void mind_answer_owns(struct codeindex *ci, const char *subject,
                             struct json_value *rows, char *summary,
                             size_t cap)
{
    struct ci_file file;
    bool found = false;
    if (codeindex_file(ci, subject, &file, &found) && found) {
        mind_push_row(rows, file.group, file.path, 0, file.purpose);
        (void)snprintf(summary, cap, "%s belongs to group %s", file.path,
                       file.group);
        return;
    }
    struct ci_symbol sym;
    if (codeindex_symbol(ci, subject, &sym, &found) && found &&
        sym.group[0]) {
        mind_push_row(rows, sym.group,
                      sym.def_path[0] ? sym.def_path : sym.decl_path,
                      sym.def_path[0] ? sym.def_line : sym.decl_line,
                      sym.signature);
        (void)snprintf(summary, cap, "%s is defined in group %s", sym.name,
                       sym.group);
        return;
    }
    (void)snprintf(summary, cap,
                   "the index holds neither a file nor a symbol named '%s', "
                   "so it cannot say who owns it", subject);
}

/* The shared impact resolver, not a copy of it. It names the groups a change
 * to this path touches; which ONE group the proof routes to is `code tests`,
 * and that policy is deliberately not restated here. */
static void mind_answer_tests_for(const char *subject, struct json_value *rows,
                                  char *summary, size_t cap)
{
    struct agent_impact_acc acc;
    memset(&acc, 0, sizeof(acc));
    (void)agent_impact_apply_shared_rules(subject, &acc);
    for (size_t i = 0; i < acc.groups_len; i++)
        mind_push_row(rows, acc.groups[i], subject, 0,
                      "shared impact rule match");
    if (acc.groups_len > 0)
        (void)snprintf(summary, cap,
                       "%zu group(s) cover %s; `z23 code tests %s` names the "
                       "one the proof routes to",
                       acc.groups_len, subject, subject);
    else
        (void)snprintf(summary, cap,
                       "no shared impact rule matches %s; `z23 code tests %s` "
                       "gives the routing floor", subject, subject);
}

/* Two questions this baseline cannot answer, said as facts rather than
 * failures. `dev know` and the fleet fact tables are not in this tree, and
 * the forward half of the story graph has not landed; a mind that answered
 * anyway would be inventing the very rows those lanes exist to measure. */
static void mind_answer_not_yet(const char *kind, struct json_value *data,
                                char *summary, size_t cap)
{
    const char *needs =
        strcmp(kind, "next_passage") == 0
            ? "the story walker (forward passages, requires, choices)"
            : strcmp(kind, "executor_for") == 0
                  ? "the fleet observation rows and the `dev know` leaf"
                  : "the trap_signature fact rows and the `dev know` leaf";
    (void)json_push_kv_str(data, "not_yet_available", needs);
    (void)snprintf(summary, cap,
                   "not_yet_available: answering '%s' needs %s, which is not "
                   "in this tree. This is a statement about what exists, not "
                   "a failed lookup", kind, needs);
}

void zcl_native_handle_dev_mind_ask(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    const char *kind = mind_str(request, "kind");
    const char *subject = mind_str(request, "subject");
    bool known = false;
    for (size_t i = 0; kind && i < sizeof(g_mind_kinds) / sizeof(*g_mind_kinds);
         i++)
        known = known || strcmp(kind, g_mind_kinds[i]) == 0;
    if (!known) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "UNKNOWN_QUESTION", "normalize", false, false,
            "kind must be one of where_is, owns, tests_for, executor_for, "
            "next_passage, trap_of", kind ? kind : "");
        return;
    }
    bool needs_index = strcmp(kind, "where_is") == 0 ||
                       strcmp(kind, "owns") == 0;
    if (!subject && strcmp(kind, "next_passage") != 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_SUBJECT",
                               "normalize", false, false,
                               "this question needs a subject, for example "
                               "{\"kind\":\"where_is\",\"subject\":"
                               "\"codeindex_open\"}", kind);
        return;
    }

    const char *root = mind_source_root(request);
    long long now = (long long)platform_time_wall_time_t();
    char summary[512];
    summary[0] = '\0';
    char index_root[65];
    index_root[0] = '\0';
    long long age_s = codeindex_generation_age_s(root, now);
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);

    struct codeindex *ci = NULL;
    if (needs_index) {
        bool stale = true;
        ci = codeindex_open_readonly(root, &stale);
        if (!ci) {
            json_free(&rows);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_BLOCKED,
                ZCL_COMMAND_EXIT_TRANSIENT, "INDEX_ABSENT", "dispatch", true,
                false,
                "this checkout has no code index yet, and asking never "
                "builds one. Start a mind for it, or run `z23 code map` once "
                "to build the first generation.", root);
            return;
        }
        mind_index_root(ci, index_root);
        if (stale) {
            codeindex_close(ci);
            json_free(&rows);
            mind_refuse_stale(reply, root, age_s, index_root);
            return;
        }
        if (strcmp(kind, "where_is") == 0)
            mind_answer_where_is(ci, subject, &rows, summary, sizeof(summary));
        else
            mind_answer_owns(ci, subject, &rows, summary, sizeof(summary));
        codeindex_close(ci);
    } else if (strcmp(kind, "tests_for") == 0) {
        mind_answer_tests_for(subject, &rows, summary, sizeof(summary));
    } else {
        mind_answer_not_yet(kind, &reply->data, summary, sizeof(summary));
    }

    (void)json_push_kv_str(&reply->data, "schema", "zcl.mind_answer.v1");
    (void)json_push_kv_str(&reply->data, "kind", kind);
    (void)json_push_kv_str(&reply->data, "subject", subject ? subject : "");
    (void)json_push_kv(&reply->data, "rows", &rows);
    (void)json_push_kv_int(&reply->data, "row_count",
                           (int64_t)json_size(&rows));
    json_free(&rows);
    (void)json_push_kv_str(&reply->data, "index_root", index_root);
    (void)json_push_kv_int(&reply->data, "index_age_s",
                           needs_index ? age_s : -1);
    (void)json_push_kv_bool(&reply->data, "stale", false);
    (void)json_push_kv_str(&reply->data, "source", "local");
    (void)json_push_kv_str(&reply->data, "summary", summary);
}

/* ── status ───────────────────────────────────────────────────────────── */

/* The same numbers, read straight from the checkout's published generation
 * when no resident has published a heartbeat for it. A box with no mind still
 * has an index, and a metrics answer that reported nothing there would be
 * describing the resident rather than the index. Read-only: this never
 * rebuilds, and a stale generation is reported as stale, not refreshed. */
static void mind_status_direct(struct zcl_command_reply *reply,
                               const char *root, long long now)
{
    bool stale = true;
    struct codeindex *ci = codeindex_open_readonly(root, &stale);
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "root", root);
    (void)json_push_kv_bool(&row, "indexed", ci != NULL);
    (void)json_push_kv_bool(&row, "stale", ci ? stale : true);
    (void)json_push_kv_int(&row, "index_age_s",
                           codeindex_generation_age_s(root, now));
    (void)json_push_kv_int(&row, "index_bytes",
                           codeindex_generation_bytes(root));
    if (ci) {
        char index_root[65];
        mind_index_root(ci, index_root);
        (void)json_push_kv_str(&row, "index_root", index_root);
        struct ci_row_counts counts;
        if (codeindex_row_counts(ci, &counts)) {
            (void)json_push_kv_int(&row, "files", counts.files);
            (void)json_push_kv_int(&row, "symbols", counts.symbols);
            (void)json_push_kv_int(&row, "includes", counts.includes);
            (void)json_push_kv_int(&row, "refs", counts.refs);
            (void)json_push_kv_int(&row, "group_count", counts.groups);
        }
        long long cold_ms = 0, cold_files = 0;
        (void)codeindex_build_cold_ms(ci, &cold_ms, &cold_files);
        (void)json_push_kv_int(&row, "build_cold_ms", cold_ms);
        (void)json_push_kv_int(&row, "build_cold_files", cold_files);
        codeindex_close(ci);
    }
    (void)json_push_kv_bool(&row, "owned", codeindex_owner_is_live(root, now));
    (void)json_push_kv(&reply->data, "checkout", &row);
    json_free(&row);
    (void)json_push_kv_str(&reply->data, "checkout_source", "read_directly");
}

static void mind_status_local(struct zcl_command_reply *reply, long long now,
                              bool *running_out)
{
    struct zcl_mind_heartbeat beat;
    bool have = zcl_mind_heartbeat_read(&beat);
    *running_out = have &&
                   now - beat.beat_unix <= CODEINDEX_OWNER_HEARTBEAT_MAX_AGE_S;
    (void)json_push_kv_bool(&reply->data, "running", *running_out);
    if (!have) {
        (void)json_push_kv_str(&reply->data, "state", "no_heartbeat");
        return;
    }
    (void)json_push_kv_str(&reply->data, "state",
                           *running_out ? "running" : "heartbeat_expired");
    (void)json_push_kv_int(&reply->data, "pid", beat.pid);
    (void)json_push_kv_int(&reply->data, "started_unix", beat.started_unix);
    (void)json_push_kv_int(&reply->data, "beat_unix", beat.beat_unix);
    (void)json_push_kv_int(&reply->data, "beat_age_s", now - beat.beat_unix);
    (void)json_push_kv_int(&reply->data, "last_rebuild_ms",
                           beat.last_rebuild_ms);
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < beat.checkout_count; i++) {
        const struct zcl_mind_checkout *c = &beat.checkouts[i];
        struct json_value row, groups;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "root", c->root);
        (void)json_push_kv_str(&row, "index_root", c->index_root);
        (void)json_push_kv_int(&row, "index_age_s", c->index_age_s);
        (void)json_push_kv_int(&row, "last_rebuild_ms", c->last_rebuild_ms);
        (void)json_push_kv_int(&row, "last_rebuild_unix", c->last_rebuild_unix);
        (void)json_push_kv_int(&row, "rebuilds", c->rebuilds);
        (void)json_push_kv_bool(&row, "indexed", c->indexed);
        (void)json_push_kv_bool(&row, "stale", c->stale);
        /* What the generation holds. files and symbols are separate facts:
         * a file the scanner admitted but could not parse contributes a file
         * row and no symbols, and one number for both would report coverage
         * the index does not have. build_cold_* is the store's own receipt
         * for the last FULL build; an incremental refresh never rewrites it,
         * so it always describes a cold build and never this one. */
        (void)json_push_kv_int(&row, "files", c->files);
        (void)json_push_kv_int(&row, "symbols", c->symbols);
        (void)json_push_kv_int(&row, "includes", c->includes);
        (void)json_push_kv_int(&row, "refs", c->refs);
        (void)json_push_kv_int(&row, "group_count", (int64_t)c->group_count);
        (void)json_push_kv_int(&row, "index_bytes", c->index_bytes);
        (void)json_push_kv_int(&row, "build_cold_ms", c->build_cold_ms);
        (void)json_push_kv_int(&row, "build_cold_files", c->build_cold_files);
        (void)json_push_kv_bool(&row, "owned",
                                codeindex_owner_is_live(c->root, now));
        json_init(&groups);
        json_set_array(&groups);
        for (size_t g = 0; g < c->group_count; g++) {
            struct json_value grow;
            json_init(&grow);
            json_set_object(&grow);
            (void)json_push_kv_str(&grow, "name", c->groups[g].name);
            (void)json_push_kv_int(&grow, "files", c->groups[g].files);
            (void)json_push_back(&groups, &grow);
            json_free(&grow);
        }
        (void)json_push_kv(&row, "groups", &groups);
        json_free(&groups);
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "checkouts", &rows);
    (void)json_push_kv_int(&reply->data, "checkout_count",
                           (int64_t)beat.checkout_count);
    json_free(&rows);
}

/* The fleet half asks the LOCAL node for its durable machine view and reads
 * the mind row each peer's signed capsule carried. It never opens a datadir
 * and never dials a peer: the pull already happened on the mesh status
 * cadence, and this is a read of what that pull recorded. */
static bool mind_status_fleet(struct zcl_command_reply *reply)
{
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("mesh_machines", "[]");
    if (!raw) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
            "NODE_UNAVAILABLE", "dispatch", true, false,
            "no local node answered. Peer mind rows arrive inside signed "
            "mesh-status receipts the node collects; without a node there is "
            "nothing collected to read, and this command never dials a peer "
            "itself.", "dev.mind");
        return false;
    }
    struct json_value body;
    json_init(&body);
    bool ok = json_read(&body, raw, strlen(raw)) && body.type == JSON_OBJ;
    free(raw);
    const struct json_value *machines = ok ? json_get(&body, "machines")
                                           : NULL;
    if (!machines || machines->type != JSON_ARR) {
        json_free(&body);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_MACHINE_BODY",
                               "serialize", false, false,
                               "the node returned no machine list",
                               "dev.mind");
        return false;
    }
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    int64_t with_mind = 0;
    for (size_t i = 0; i < json_size(machines); i++) {
        const struct json_value *m = json_at(machines, i);
        if (!m || m->type != JSON_OBJ) continue;
        const struct json_value *root = json_get(m, "mind_index_root");
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "pairing_id",
                               json_get_str(json_get(m, "pairing_id")));
        (void)json_push_kv_str(&row, "observation_state",
                               json_get_str(json_get(m, "observation_state")));
        if (root && root->type == JSON_STR) {
            with_mind++;
            (void)json_push_kv_str(&row, "index_root", json_get_str(root));
            (void)json_push_kv_int(
                &row, "index_age_s",
                json_get_int(json_get(m, "mind_index_age_s")));
            (void)json_push_kv_int(
                &row, "checkouts", json_get_int(json_get(m, "mind_checkouts")));
        } else {
            /* A peer that carried no mind row said nothing about its index.
             * That is not the same as a peer with an empty index. */
            (void)json_push_kv_str(&row, "index_root", "");
            (void)json_push_kv_str(&row, "mind", "not_reported");
        }
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "peers", &rows);
    (void)json_push_kv_int(&reply->data, "peer_count",
                           (int64_t)json_size(&rows));
    (void)json_push_kv_int(&reply->data, "peers_with_mind", with_mind);
    json_free(&rows);
    json_free(&body);
    return true;
}

void zcl_native_handle_dev_mind_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    long long now = (long long)platform_time_wall_time_t();
    bool running = false;
    (void)json_push_kv_str(&reply->data, "schema", "zcl.mind_status.v1");
    mind_status_local(reply, now, &running);
    if (!running)
        mind_status_direct(reply, mind_source_root(request), now);
    if (mind_flag(request, "fleet") && !mind_status_fleet(reply))
        return;
    char summary[320];
    (void)snprintf(summary, sizeof(summary),
                   running ? "a mind is running on this node"
                           : "no mind is running on this node; every query "
                             "here rebuilds the index for itself");
    (void)json_push_kv_str(&reply->data, "summary", summary);
}

/* ── serve ────────────────────────────────────────────────────────────── */

void zcl_native_handle_dev_mind_serve(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    long long cycles = -1;
    const struct json_value *v = json_get(request->input, "cycles");
    if (v && v->type == JSON_INT)
        cycles = (long long)json_get_int(v);
    if (zcl_mind_serve(NULL, NULL, cycles) != 0) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
            "MIND_NOT_STARTED", "dispatch", true, false,
            "the resident did not start: either another mind already holds "
            "this node, or no checkout is registered. Register one by writing "
            "the checkouts state file, then start it again.", "dev.mind");
        return;
    }
    (void)json_push_kv_str(&reply->data, "schema", "zcl.mind_serve.v1");
    (void)json_push_kv_str(&reply->data, "state", "retired");
    (void)json_push_kv_str(&reply->data, "summary",
                           "the mind retired: its checkout registry was "
                           "removed or it was asked to stop");
}
