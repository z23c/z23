/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.ready and dev.agent.test — the two questions an agent
 *          asks a checkout most often ("can this build ship?" and "did that
 *          test group actually RUN and pass?"), answered as one typed
 *          zcl.result.v1 envelope so no agent has to compose shell or
 *          remember a recipe. Every refusal names the exact command that
 *          fixes it. */

#include "command/native_command.h"
#include "command/native_devagent.h"

#include "base/safe_alloc.h"
#include "controllers/shop_native_handler.h"
#include "json/json.h"
#include "util/spawn.h"

#include "dev/test_group_catalog.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <sys/resource.h>
#endif

#define DVA_READY_PATH "dev.agent.ready"
#define DVA_TEST_PATH  "dev.agent.test"

/* One group's transcript plus the runner's summary. Sized so the SUITE
 * VERDICT line — which the runner prints near the END of stdout — can never
 * fall off the end of an ordinary focused run. A capture that hits this cap
 * is reported as truncated and refused rather than parsed. */
#define DVA_CAPTURE_BYTES (8u * 1024u * 1024u)

/* ── shared refusal shape ──────────────────────────────────────────────────
 * A refusal that does not name the command that fixes it is a dead end. Every
 * caller below goes through this, so `next_action` can never be forgotten. */
static void dva_refuse(struct zcl_command_reply *reply,
                       enum zcl_command_status status,
                       enum zcl_command_exit exit_code, const char *code,
                       const char *phase, const char *message,
                       const char *evidence, const char *next_action)
{
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false, false,
                           message, evidence);
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", next_action ? next_action : "");
    reply->error.human_action_required = true;
}

static const char *dva_str(const struct json_value *input, const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static bool dva_bool(const struct json_value *input, const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v && json_get_bool(v);
}

static int64_t dva_int(const struct json_value *input, const char *key,
                       int64_t fallback)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : fallback;
}

static bool dva_file_present(const char *root, const char *rel)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, rel);
    return n > 0 && (size_t)n < sizeof(path) && access(path, R_OK) == 0;
}

static bool dva_exec_present(const char *root, const char *rel)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, rel);
    return n > 0 && (size_t)n < sizeof(path) && access(path, X_OK) == 0;
}

static bool dva_push_check(struct json_value *arr, const char *name, bool ok,
                           const char *detail)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    bool pushed = json_push_kv_str(&item, "check", name) &&
                  json_push_kv_bool(&item, "ok", ok) &&
                  json_push_kv_str(&item, "detail", detail) &&
                  json_push_back(arr, &item);
    json_free(&item);
    return pushed;
}

/* Resolve the checkout this command is being asked about, or refuse naming
 * the move that fixes it. */
static bool dva_root(struct zcl_command_reply *reply, const char *leaf,
                     char out[PATH_MAX])
{
    if (zcl_devagent_checkout_root(NULL, out, PATH_MAX))
        return true;
    char next[256];
    (void)snprintf(next, sizeof(next),
                   "cd into a Z23 checkout (the directory holding Makefile and "
                   "config/commands/root.def), then rerun: z23 %s",
                   strcmp(leaf, DVA_READY_PATH) == 0 ? "dev agent ready"
                                                     : "dev agent test");
    dva_refuse(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
               "NOT_IN_A_CHECKOUT", "resolve",
               "no Z23 checkout root above the current directory", leaf, next);
    return false;
}

/* ── dev.agent.ready ────────────────────────────────────────────────────── */

/* The archives `make z23` links. A worktree that is missing any of them
 * cannot link at all; a worktree missing only the vendor/tor set links the
 * Tor STUB, passes every test, and is refused at deploy — the failure this
 * command exists to make visible in one call instead of after a 25-minute
 * ship gate. */
static const char *const g_vendor_archives[] = {
    "vendor/lib/libcrypto.a", "vendor/lib/libssl.a", "vendor/lib/libevent.a",
    "vendor/lib/libevent_openssl.a", "vendor/lib/libevent_pthreads.a",
    "vendor/lib/libsqlite3.a", "vendor/lib/libz.a",
    "vendor/lib/libtor_stub.a",
};

static const char *const g_tor_archives[] = {
    "vendor/tor/libtor.a",
    "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
    "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
    "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
};

static size_t dva_count_missing(const char *root, const char *const *rel,
                                size_t count, char *first_missing,
                                size_t cap)
{
    size_t missing = 0;
    if (first_missing && cap)
        first_missing[0] = '\0';
    for (size_t i = 0; i < count; i++) {
        if (dva_file_present(root, rel[i]))
            continue;
        if (missing == 0 && first_missing && cap)
            (void)snprintf(first_missing, cap, "%s", rel[i]);
        missing++;
    }
    return missing;
}

void zcl_native_handle_dev_agent_ready(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char root[PATH_MAX];
    if (!dva_root(reply, DVA_READY_PATH, root))
        return;

    /* The link fact, read from the binary that is answering — the same weak
     * symbol network telemetry reads for tor_build. No second source of
     * truth, and no jsonq hop to extract it. */
    bool tor_real = shop_tor_real_build_linked();

    char first_vendor[128], first_tor[128];
    size_t vendor_missing = dva_count_missing(
        root, g_vendor_archives,
        sizeof(g_vendor_archives) / sizeof(g_vendor_archives[0]),
        first_vendor, sizeof(first_vendor));
    size_t tor_missing = dva_count_missing(
        root, g_tor_archives,
        sizeof(g_tor_archives) / sizeof(g_tor_archives[0]),
        first_tor, sizeof(first_tor));
    bool submodule = dva_file_present(root, "vendor/tor/.git");
    bool sqlite_amalgam = dva_file_present(root, "vendor/sqlite3.c");
    bool node_binary = dva_exec_present(root, "build/bin/z23");
    bool test_runner = dva_exec_present(root, "build/bin/test_parallel");

    bool can_link = vendor_missing == 0 && sqlite_amalgam;
    bool can_link_real_tor = submodule && tor_missing == 0;
    /* node_binary is part of the verdict, not just a reported row. Without it
     * this command could answer shippable=true while build/bin/z23 does not
     * exist — the answering process can be a binary that was deleted after it
     * started, or a z23 from another checkout on PATH, and tor_real is read
     * from whatever is answering. A "can this checkout produce a shippable
     * candidate" verdict that ignores whether the candidate is on disk is
     * exactly the kind of green this whole surface exists to stop. */
    bool shippable = can_link && can_link_real_tor && tor_real && node_binary;

    const char *blocker = "NONE";
    char next_action[256];
    (void)snprintf(next_action, sizeof(next_action),
                   "./tools/agent_fast_ci.sh verify-change");
    if (!can_link) {
        blocker = "VENDOR_ARCHIVES_MISSING";
        (void)snprintf(next_action, sizeof(next_action), "make worktree-prime");
    } else if (!can_link_real_tor) {
        blocker = "TOR_ARCHIVES_MISSING";
        (void)snprintf(next_action, sizeof(next_action), "make worktree-prime");
    } else if (!tor_real) {
        blocker = "BINARY_LINKED_TOR_STUB";
        (void)snprintf(next_action, sizeof(next_action),
                       "make -j\"$(getconf _NPROCESSORS_ONLN)\" z23 "
                       "(the archives are here now; this binary predates them)");
    } else if (!node_binary) {
        blocker = "NODE_BINARY_NOT_BUILT";
        (void)snprintf(next_action, sizeof(next_action),
                       "make -j\"$(getconf _NPROCESSORS_ONLN)\" z23 "
                       "(the archives are here; the candidate is not on disk)");
    } else if (!test_runner) {
        blocker = "TEST_RUNNER_NOT_BUILT";
        (void)snprintf(next_action, sizeof(next_action),
                       "make -j\"$(getconf _NPROCESSORS_ONLN)\" test_parallel");
    }

    struct json_value checks;
    json_init(&checks);
    json_set_array(&checks);
    char detail[192];
    (void)snprintf(detail, sizeof(detail), "%zu of %zu archives missing%s%s",
                   vendor_missing,
                   sizeof(g_vendor_archives) / sizeof(g_vendor_archives[0]),
                   vendor_missing ? "; first: " : "",
                   vendor_missing ? first_vendor : "");
    (void)dva_push_check(&checks, "vendor_archives", vendor_missing == 0, detail);
    (void)dva_push_check(&checks, "vendor_sqlite3_amalgam", sqlite_amalgam,
                         sqlite_amalgam ? "vendor/sqlite3.c present"
                                        : "vendor/sqlite3.c absent — the "
                                          "Windows cross-build has no rule for it");
    (void)dva_push_check(&checks, "tor_submodule_initialized", submodule,
                         submodule ? "vendor/tor is a populated submodule"
                                   : "vendor/tor is an empty gitlink; a git "
                                     "worktree does not inherit submodules");
    (void)snprintf(detail, sizeof(detail), "%zu of %zu archives missing%s%s",
                   tor_missing,
                   sizeof(g_tor_archives) / sizeof(g_tor_archives[0]),
                   tor_missing ? "; first: " : "",
                   tor_missing ? first_tor : "");
    (void)dva_push_check(&checks, "tor_archives", tor_missing == 0, detail);
    (void)dva_push_check(&checks, "linked_tor_is_real", tor_real,
                         tor_real ? "this binary linked vendor/tor/libtor.a"
                                  : "this binary linked libtor_stub.a — it "
                                    "passes every test and the ship step "
                                    "refuses its candidate");
    (void)dva_push_check(&checks, "node_binary_built", node_binary,
                         node_binary ? "build/bin/z23 is executable"
                                     : "build/bin/z23 absent");
    (void)dva_push_check(&checks, "test_runner_built", test_runner,
                         test_runner ? "build/bin/test_parallel is executable"
                                     : "build/bin/test_parallel absent");

    (void)json_push_kv_str(&reply->data, "schema", "zcl.agent_ready.v1");
    (void)json_push_kv_str(&reply->data, "checkout_root", root);
    (void)json_push_kv_str(&reply->data, "tor_build",
                           tor_real ? "real_tor" : "tor_stub");
    (void)json_push_kv_bool(&reply->data, "can_link", can_link);
    (void)json_push_kv_bool(&reply->data, "can_link_real_tor",
                            can_link_real_tor);
    (void)json_push_kv_bool(&reply->data, "shippable", shippable);
    (void)json_push_kv_str(&reply->data, "blocker", blocker);
    (void)json_push_kv(&reply->data, "checks", &checks);
    json_free(&checks);
    (void)json_push_kv_str(&reply->data, "next_action", next_action);
    (void)json_push_kv_str(
        &reply->data, "means",
        shippable
            ? "the archives a real-Tor link needs are here, build/bin/z23 "
              "exists, and the ANSWERING binary linked real Tor — run this "
              "through the z23 you just built, or tor_build describes a "
              "different binary than the one on disk"
            : "this checkout cannot produce a shippable candidate yet; "
              "next_action names the exact fix");
}

/* ── dev.agent.test ─────────────────────────────────────────────────────── */

static bool dva_group_chars_ok(const char *group)
{
    if (!group || !group[0] || strlen(group) >= 64)
        return false;
    for (const char *p = group; *p; p++) {
        bool ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '_' || *p == '-';
        if (!ok)
            return false;
    }
    return true;
}

/* Catalog rows containing `needle`, in registry order. Also used to build the
 * suggestion list on an unknown group, because a refusal that lists real
 * neighbouring group names costs one call instead of a `--list` round trip. */
static size_t dva_catalog_matches(const char *needle, struct json_value *arr,
                                  size_t cap)
{
    size_t total = 0;
    size_t count = zcl_test_group_catalog_count();
    for (size_t i = 0; i < count; i++) {
        const char *name = zcl_test_group_catalog_at(i);
        if (!name || !strstr(name, needle))
            continue;
        total++;
        if (arr && total <= cap) {
            struct json_value item;
            json_init(&item);
            json_set_str(&item, name);
            (void)json_push_back(arr, &item);
            json_free(&item);
        }
    }
    return total;
}

/* A short prefix of the query usually still hits the right family
 * (`accep` -> accept_to_mempool), so an unknown group can still be answered
 * with real names instead of "no match". `first` receives one name the caller
 * can put verbatim into a runnable command; `list` receives the whole set as
 * evidence. */
static void dva_suggestions(const char *group, char *first, size_t first_cap,
                            char *list, size_t list_cap)
{
    first[0] = '\0';
    list[0] = '\0';
    size_t written = 0;
    for (size_t take = strlen(group); take >= 3 && written == 0; take--) {
        char prefix[64];
        (void)snprintf(prefix, sizeof(prefix), "%.*s", (int)take, group);
        size_t count = zcl_test_group_catalog_count();
        for (size_t i = 0; i < count && written < 5; i++) {
            const char *name = zcl_test_group_catalog_at(i);
            if (!name || !strstr(name, prefix))
                continue;
            if (written == 0)
                (void)snprintf(first, first_cap, "%s", name);
            size_t used = strlen(list);
            int n = snprintf(list + used, list_cap - used, "%s%s",
                             written ? ", " : "", name);
            if (n <= 0 || (size_t)n >= list_cap - used)
                break;
            written++;
        }
    }
}

struct dva_run {
    char runner[PATH_MAX];
    char selector[128];
    char command_line[512];
    int exit_code;
    bool truncated;
};

/* ── bounded process helpers (shared with dev.agent.mutate) ─────────────── */

/* The runner and the build both resolve paths relative to the checkout root,
 * so both run from there whatever directory the agent invoked z23 in. The
 * caller's directory is put back before returning on every path. */
static int dva_spawn_at(const char *root, const char *const argv[], char *buf,
                        size_t cap, int timeout_ms)
{
    char previous[PATH_MAX];
    bool moved = false;
    if (getcwd(previous, sizeof(previous)) && chdir(root) == 0)
        moved = true;
    int rc = zcl_spawn_capture(argv, buf, cap, timeout_ms);
    /* The child has already run and its status is the answer. A failed
     * restore cannot un-run it, and reporting it as a launch failure would
     * be a lie; the process is about to exit anyway. */
    if (moved)
        (void)!chdir(previous);
    return rc;
}

int zcl_devagent_run_make(const char *root, const char *target, int timeout_ms)
{
    if (!root || !target)
        return -1;
    char jobs[32];
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    (void)snprintf(jobs, sizeof(jobs), "-j%ld", online > 0 ? online : 1);
    const char *argv[] = { "make", "--no-print-directory", jobs, target, NULL };
    char *buf = zcl_malloc(DVA_CAPTURE_BYTES, "devagent.capture");
    if (!buf)
        return -1;
    buf[0] = '\0';
    int rc = dva_spawn_at(root, argv, buf, DVA_CAPTURE_BYTES, timeout_ms);
    free(buf);
    return rc;
}

int zcl_devagent_run_group(const char *root, const char *selector,
                           int timeout_ms, struct zcl_devagent_verdict *out,
                           bool *truncated)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (truncated)
        *truncated = false;
    if (!root || !selector || !out)
        return -1;
    char runner[PATH_MAX];
    int n = snprintf(runner, sizeof(runner), "%s/build/bin/test_parallel", root);
    if (n <= 0 || (size_t)n >= sizeof(runner) || access(runner, X_OK) != 0)
        return -1;
    const char *argv[] = { runner, selector, "--no-cache", NULL };
    char *buf = zcl_malloc(DVA_CAPTURE_BYTES, "devagent.capture");
    if (!buf)
        return -1;
    buf[0] = '\0';
    int rc = dva_spawn_at(root, argv, buf, DVA_CAPTURE_BYTES, timeout_ms);
    bool full = strlen(buf) >= DVA_CAPTURE_BYTES - 1;
    if (truncated)
        *truncated = full;
    if (!full)
        (void)zcl_devagent_verdict_parse(buf, out);
    free(buf);
    return rc;
}

static void dva_stack_limits(struct json_value *data)
{
#if !defined(_WIN32)
    struct rlimit lim;
    if (getrlimit(RLIMIT_STACK, &lim) != 0)
        return;
    (void)json_push_kv_int(data, "caller_stack_rlimit_soft",
                           lim.rlim_cur == RLIM_INFINITY
                               ? -1
                               : (int64_t)lim.rlim_cur);
    (void)json_push_kv_int(data, "caller_stack_rlimit_hard",
                           lim.rlim_max == RLIM_INFINITY
                               ? -1
                               : (int64_t)lim.rlim_max);
#else
    (void)data;
#endif
}

void zcl_native_handle_dev_agent_test(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *input = request->input;
    const char *group = dva_str(input, "group");
    if (!dva_group_chars_ok(group)) {
        dva_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "MISSING_TEST_GROUP", "validate",
                   "group must be a registered test group name or a substring "
                   "of one ([A-Za-z0-9_-], under 64 characters)",
                   "group",
                   "z23 dev agent test --group=hex_codec  "
                   "(names come from tools/dev/test_group_catalog.def)");
        return;
    }
    char root[PATH_MAX];
    if (!dva_root(reply, DVA_TEST_PATH, root))
        return;

    bool want_exact = dva_bool(input, "exact");
    char full[ZCL_TEST_GROUP_FULL_MAX];
    bool exact_ok = zcl_test_group_resolve_exact(group, full);
    size_t matches = dva_catalog_matches(group, NULL, 0);

    if ((want_exact && !exact_ok) || (matches == 0 && !exact_ok)) {
        char one[96], list[256], next[256], msg[192];
        dva_suggestions(group, one, sizeof(one), list, sizeof(list));
        if (one[0])
            (void)snprintf(next, sizeof(next),
                           "z23 dev agent test --group=%s", one);
        else
            (void)snprintf(next, sizeof(next),
                           "build/bin/test_parallel --list  (nothing in the "
                           "registered catalog resembles '%s')", group);
        (void)snprintf(msg, sizeof(msg),
                       want_exact
                           ? "'%s' is not one canonical registered test group"
                           : "no registered test group contains '%s'; a "
                             "selector that matches nothing must never look "
                             "like a pass",
                       group);
        dva_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "UNKNOWN_TEST_GROUP", "resolve", msg,
                   list[0] ? list : "no catalog row shares this prefix", next);
        return;
    }

    struct dva_run run;
    memset(&run, 0, sizeof(run));
    run.exit_code = -1;
    (void)snprintf(run.runner, sizeof(run.runner), "%s/build/bin/test_parallel",
                   root);
    if (access(run.runner, X_OK) != 0) {
        dva_refuse(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                   "TEST_RUNNER_NOT_BUILT", "precondition",
                   "build/bin/test_parallel is absent; `make test_parallel` "
                   "BUILDS the runner and runs nothing, so it must be built "
                   "before a group can run",
                   run.runner,
                   "make -j\"$(getconf _NPROCESSORS_ONLN)\" test_parallel");
        (void)zcl_command_reply_add_next(
            reply, "dev.agent.ready", "{}",
            "see what else this checkout is missing before building");
        return;
    }

    /* Exact beats substring whenever the query resolves: an exact selector
     * cannot silently drag in a neighbouring group. */
    bool use_exact = want_exact || exact_ok;
    (void)snprintf(run.selector, sizeof(run.selector), "--%s=%s",
                   use_exact ? "exact" : "only", use_exact ? full : group);

    /* --no-cache is not an option here. A cached verdict is a claim about an
     * earlier binary; this command exists to answer "did it run NOW". */
    (void)snprintf(run.command_line, sizeof(run.command_line), "%s %s %s",
                   run.runner, run.selector, "--no-cache");

    /* Absent means "as long as a focused group plausibly needs"; a supplied
     * value is honoured, never silently replaced by the default. */
    int64_t timeout_ms = dva_int(input, "timeout_ms", 900000);
    if (timeout_ms < 1000)
        timeout_ms = 1000;
    if (timeout_ms > 3600000)
        timeout_ms = 3600000;

    struct zcl_devagent_verdict verdict;
    run.exit_code = zcl_devagent_run_group(root, run.selector, (int)timeout_ms,
                                           &verdict, &run.truncated);
    bool parsed = verdict.present;

    if (!parsed) {
        char msg[192];
        (void)snprintf(msg, sizeof(msg),
                       "the runner printed no SUITE VERDICT line (exit %d%s); "
                       "nothing about this run may be read as a pass",
                       run.exit_code, run.truncated ? ", output truncated" : "");
        dva_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                   "NO_SUITE_VERDICT", "verify", msg, run.command_line,
                   run.command_line);
        return;
    }

    char verdict_line[256];
    (void)snprintf(verdict_line, sizeof(verdict_line),
                   "mode=%s groups_ran=%lld groups_failed=%lld "
                   "groups_gated=%lld groups_cached=%lld self_skips=%lld "
                   "env_unobserved=%lld",
                   verdict.mode, verdict.groups_ran, verdict.groups_failed,
                   verdict.groups_gated, verdict.groups_cached,
                   verdict.self_skips, verdict.env_unobserved);

    if (verdict.groups_ran <= 0) {
        char msg[192];
        (void)snprintf(msg, sizeof(msg),
                       "selector '%s' executed 0 groups (%lld gated, %lld "
                       "served from cache) — a group that did not run is not "
                       "a pass", run.selector, verdict.groups_gated,
                       verdict.groups_cached);
        dva_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                   "NO_GROUP_RAN", "verify", msg, verdict_line,
                   "ZCL_STRESS_TESTS=1 ZCL_PARAMS_TESTS=1 z23 dev agent test "
                   "--group=<name> --exact=true  (a gated group needs its "
                   "opt-in env before it executes)");
        return;
    }
    if (verdict.groups_failed > 0) {
        char msg[192];
        (void)snprintf(msg, sizeof(msg),
                       "%lld of %lld executed group(s) FAILED",
                       verdict.groups_failed, verdict.groups_ran);
        char next[256];
        (void)snprintf(next, sizeof(next), "%s --verbose", run.command_line);
        dva_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                   "TEST_GROUP_FAILED", "verify", msg, verdict_line, next);
        return;
    }

    struct json_value matched;
    json_init(&matched);
    json_set_array(&matched);
    (void)dva_catalog_matches(use_exact ? full : group, &matched, 16);

    (void)json_push_kv_str(&reply->data, "schema", "zcl.agent_test_run.v1");
    (void)json_push_kv_str(&reply->data, "checkout_root", root);
    (void)json_push_kv_str(&reply->data, "runner", run.runner);
    (void)json_push_kv_str(&reply->data, "command", run.command_line);
    (void)json_push_kv_str(&reply->data, "selector",
                           use_exact ? "exact" : "only");
    (void)json_push_kv_str(&reply->data, "group_query", group);
    if (use_exact)
        (void)json_push_kv_str(&reply->data, "group_resolved", full);
    (void)json_push_kv_int(&reply->data, "catalog_matches", (int64_t)matches);
    (void)json_push_kv(&reply->data, "matched_groups", &matched);
    json_free(&matched);
    (void)json_push_kv_str(&reply->data, "mode", verdict.mode);
    (void)json_push_kv_int(&reply->data, "groups_ran", verdict.groups_ran);
    (void)json_push_kv_int(&reply->data, "groups_failed",
                           verdict.groups_failed);
    (void)json_push_kv_int(&reply->data, "groups_gated", verdict.groups_gated);
    (void)json_push_kv_int(&reply->data, "groups_cached",
                           verdict.groups_cached);
    (void)json_push_kv_int(&reply->data, "groups_total", verdict.groups_total);
    (void)json_push_kv_int(&reply->data, "self_skips", verdict.self_skips);
    (void)json_push_kv_int(&reply->data, "env_unobserved",
                           verdict.env_unobserved);
    (void)json_push_kv_bool(&reply->data, "hotswap_module", verdict.hotswap);
    (void)json_push_kv_str(&reply->data, "toolkey", verdict.toolkey);
    (void)json_push_kv_int(&reply->data, "runner_exit_code", run.exit_code);
    dva_stack_limits(&reply->data);
    (void)json_push_kv_str(&reply->data, "verdict_line", verdict_line);
    (void)json_push_kv_str(
        &reply->data, "means",
        "groups_ran is the only field that proves execution; self_skips and "
        "env_unobserved legs did not assert their gated contract");
    (void)json_push_kv_str(&reply->data, "next_action",
                           "./tools/agent_fast_ci.sh verify-change");
}
