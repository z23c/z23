/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the ZCODE package INSTALL lifecycle:
 *
 *   zcode package add plan     what installing <name_or_root> would do
 *   zcode package add commit   do exactly that plan, or refuse and say why
 *   zcode package rollback     re-activate the previous generation
 *   zcode package reproduce    rebuild one installed package under the
 *                              standard profile and file the second,
 *                              distinct build receipt on a byte-identical
 *                              MATCH
 *
 * These handlers parse request JSON and render reply JSON. Every decision —
 * resolution, the dependency lock, verification, the confined build, the
 * atomic install, the generation log — belongs to the single lifecycle state
 * machine in engine/services/src/package_lifecycle*.c, which is also the only
 * thing that touches disk. Nothing built or downloaded is ever loaded into
 * this process. */

#include "base/hex.h"
#include "command/native_command.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "services/package_lifecycle.h"
#include "vcs/package_checkout.h"
#include "vcs/package_reproduce.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *za_input_str(const struct json_value *input,
                                const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

static const char *za_datadir(const struct zcl_command_request *request,
                              struct zcl_command_reply *reply,
                              const char *command)
{
    const char *dd = za_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    if (dd && dd[0])
        return dd;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                           "normalize", false, false,
                           "no datadir given (input datadir or --datadir)",
                           command);
    return NULL;
}

/* The caller may pin the clock for deterministic testing; host clock
 * otherwise. Plan expiry is evaluated against this same value. */
static int64_t za_now(const struct zcl_command_request *request)
{
    const struct json_value *v = json_get(request->input, "now_unix");
    if (v)
        return json_get_int(v);
    return (int64_t)platform_time_wall_unix();
}

static void za_push_hex(struct json_value *obj, const char *key,
                        const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(obj, key, hex);
}

/* One named rejection, rendered the same way from every leaf. The rule is
 * the machine-readable code; the message explains it. */
static void za_fail(struct zcl_command_reply *reply, const char *rule,
                    const char *message, const char *command)
{
    char code[80];
    size_t o = 0;
    for (size_t i = 0; rule && rule[i] && o + 1u < sizeof(code); i++) {
        char c = rule[i];
        if (c >= 'a' && c <= 'z')
            c = (char)(c - 'a' + 'A');
        else if (c == '-')
            c = '_';
        code[o++] = c;
    }
    code[o] = '\0';
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID,
                           code[0] ? code : "ADD_REFUSED", "execute", false,
                           true, message && message[0] ? message : rule,
                           command);
}

/* ── zcode package checkout ─────────────────────────────────────────── */

void zcl_native_handle_zcode_package_checkout(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *command = "zcode.package.checkout";
    const char *datadir = za_datadir(request, reply, command);
    if (!datadir)
        return;
    const char *root_hex = za_input_str(request->input, "root");
    const char *destination = za_input_str(request->input, "destination");
    uint8_t root[32];
    if (!root_hex || !zcl_hex_decode_lower(root_hex, root, sizeof(root))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_ROOT",
                               "normalize", false, false,
                               "root must be 64 lowercase hex chars",
                               root_hex ? root_hex : "(missing)");
        return;
    }
    if (!destination || !destination[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "MISSING_DESTINATION", "normalize", false,
                               false, "destination is required", command);
        return;
    }
    struct vcs_package_store *store = vcs_package_store_open(
        datadir, vcs_package_store_quota_bytes());
    if (!store) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                               "execute", false, false,
                               "the package store failed to open", datadir);
        return;
    }
    struct vcs_package_checkout_metrics metrics;
    enum vcs_package_checkout_result result = vcs_package_checkout(
        store, root, destination, &metrics);
    vcs_package_store_close(store);
    if (result != VCS_PACKAGE_CHECKOUT_OK) {
        za_fail(reply, vcs_package_checkout_result_string(result),
                "package checkout refused; the root must be complete and "
                "the destination must not already exist", command);
        return;
    }
    (void)json_push_kv_str(&reply->data, "root", root_hex);
    (void)json_push_kv_str(&reply->data, "destination", destination);
    (void)json_push_kv_int(&reply->data, "files", metrics.files);
    (void)json_push_kv_int(&reply->data, "chunks", metrics.chunks);
    (void)json_push_kv_int(&reply->data, "bytes", (int64_t)metrics.bytes);
    (void)json_push_kv_bool(&reply->data, "executed", false);
    (void)json_push_kv_str(
        &reply->data, "note",
        "every byte was reverified against the immutable package root; "
        "checkout is inert and build/test/run remain explicit local steps");
}

/* ── bounded step-list windowing ────────────────────────────────────── */

/* Attach a plan/commit step list to the reply, honoring the framework's
 * normalized paging controls (request->cursor / request->max_items, lifted
 * from --input or the --cursor/--max-items flags by the dispatcher).
 * Without paging controls the COMPLETE list is attached unchanged and an
 * oversized reply still fails closed at serialization. With paging, only
 * rows [cursor, cursor+max_items) are attached, plus a `_page` descriptor
 * (total_items, included, omitted, truncated, next_cursor) so a shortened
 * answer always says so and names where to resume. A malformed or
 * out-of-range cursor is a named rejection, never a silent clamp.
 * Returns false only after failing the reply (caller frees `steps`). */
static bool za_push_steps_window(const struct zcl_command_request *request,
                                 struct json_value *steps,
                                 struct zcl_command_reply *reply,
                                 const char *command)
{
    size_t count = json_size(steps);
    size_t start = 0;
    bool paged = request->max_items > 0;
    if (request->cursor && request->cursor[0]) {
        paged = true;
        char *end = NULL;
        unsigned long long parsed =
            request->cursor[0] >= '0' && request->cursor[0] <= '9'
                ? strtoull(request->cursor, &end, 10)
                : 0;
        if (!end || *end != '\0' || parsed > count) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "INVALID_CURSOR",
                                   "normalize", false, false,
                                   "cursor must be a numeric step offset no "
                                   "larger than the step count", command);
            return false;
        }
        start = (size_t)parsed;
    }
    if (!paged) {
        (void)json_push_kv(&reply->data, "steps", steps);
        return true;
    }
    size_t limit = request->max_items > 0 ? request->max_items : count;
    size_t end = start + limit;
    if (end < start || end > count)
        end = count;
    struct json_value window;
    json_init(&window);
    json_set_array(&window);
    for (size_t i = start; i < end; i++) {
        struct json_value row;
        json_init(&row);
        json_copy(&row, json_at(steps, i));
        (void)json_push_back(&window, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "steps", &window);
    json_free(&window);
    struct json_value page;
    json_init(&page);
    json_set_object(&page);
    (void)json_push_kv_int(&page, "total_items", (int64_t)count);
    (void)json_push_kv_int(&page, "included", (int64_t)(end - start));
    (void)json_push_kv_int(&page, "omitted", (int64_t)(count - end));
    (void)json_push_kv_bool(&page, "truncated", end < count);
    if (end < count)
        (void)json_push_kv_int(&page, "next_cursor", (int64_t)end);
    (void)json_push_kv(&reply->data, "_page", &page);
    json_free(&page);
    return true;
}

/* ── zcode package add plan ─────────────────────────────────────────── */

void zcl_native_handle_zcode_package_add_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *command = "zcode.package.add.plan";
    const char *datadir = za_datadir(request, reply, command);
    if (!datadir)
        return;
    const char *target = za_input_str(request->input, "name_or_root");
    if (!target || !target[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_TARGET",
                               "normalize", false, false,
                               "name_or_root is required (a 64-hex package "
                               "root, publisher/package name, or exact "
                               "publisher/package@semver)", command);
        return;
    }

    struct package_lifecycle_plan_report report;
    struct zcl_result r = package_lifecycle_plan(datadir, target,
                                                 za_now(request), &report);
    if (!r.ok) {
        za_fail(reply, report.rule[0] ? report.rule : "plan-failed",
                r.message, command);
        return;
    }

    za_push_hex(&reply->data, "plan_id", report.plan_id);
    za_push_hex(&reply->data, "target_root", report.plan.target_root);
    za_push_hex(&reply->data, "lock_root", report.plan.lock_root);
    (void)json_push_kv_bool(&reply->data, "ready", report.ready);
    (void)json_push_kv_int(&reply->data, "expires_unix",
                           report.plan.expires_unix);
    (void)json_push_kv_int(&reply->data, "step_count",
                           (int64_t)report.plan.step_count);
    if (report.rule[0]) {
        (void)json_push_kv_str(&reply->data, "rule", report.rule);
        (void)json_push_kv_str(&reply->data, "detail", report.detail);
    }

    struct json_value steps;
    json_init(&steps);
    json_set_array(&steps);
    for (size_t i = 0; i < report.plan.step_count; i++) {
        const struct vcs_package_plan_step *s = &report.plan.steps[i];
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        za_push_hex(&row, "root", s->root);
        (void)json_push_kv_str(&row, "name", s->name);
        (void)json_push_kv_str(&row, "semver", s->semver);
        (void)json_push_kv_str(&row, "license", s->license);
        (void)json_push_kv_int(&row, "depth", (int64_t)s->depth);
        (void)json_push_kv_str(
            &row, "state",
            vcs_package_lifecycle_state_string(
                (enum vcs_package_lifecycle_state)s->state));
        (void)json_push_kv_bool(&row, "complete", s->complete);
        (void)json_push_kv_bool(&row, "installed", s->installed);
        (void)json_push_kv_int(&row, "total_bytes", (int64_t)s->total_bytes);
        (void)json_push_kv_int(&row, "total_chunks",
                               (int64_t)s->total_chunks);
        (void)json_push_back(&steps, &row);
        json_free(&row);
    }
    bool windowed = za_push_steps_window(request, &steps, reply, command);
    json_free(&steps);
    if (!windowed)
        return;

    (void)json_push_kv_str(
        &reply->data, "note",
        "a plan is a proposal, not an authorization: commit re-derives the "
        "dependency lock and refuses if it changed or if the plan expired. "
        "Steps are in build order (dependencies first, target last) and "
        "every one is pinned by its immutable package root");
}

/* ── zcode package add commit ───────────────────────────────────────── */

void zcl_native_handle_zcode_package_add_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *command = "zcode.package.add.commit";
    const char *datadir = za_datadir(request, reply, command);
    if (!datadir)
        return;
    const char *hex = za_input_str(request->input, "plan_id");
    uint8_t plan_id[32];
    if (!hex || !zcl_hex_decode(hex, plan_id, 32)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_PLAN_ID",
                               "normalize", false, false,
                               "plan_id must be 64 hex chars (from "
                               "'zcode package add plan')",
                               hex ? hex : "(missing)");
        return;
    }

    struct package_lifecycle_commit_report report;
    struct zcl_result r = package_lifecycle_commit(datadir, plan_id,
                                                   za_now(request), &report);

    struct json_value steps;
    json_init(&steps);
    json_set_array(&steps);
    for (size_t i = 0; i < report.step_count; i++) {
        const struct package_lifecycle_step *s = &report.steps[i];
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        za_push_hex(&row, "root", s->root);
        (void)json_push_kv_str(&row, "name", s->name);
        (void)json_push_kv_str(&row, "semver", s->semver);
        (void)json_push_kv_int(&row, "depth", (int64_t)s->depth);
        (void)json_push_kv_str(
            &row, "state",
            vcs_package_lifecycle_state_string(
                (enum vcs_package_lifecycle_state)s->state));
        (void)json_push_kv_bool(&row, "already_installed",
                                s->already_installed);
        (void)json_push_kv_bool(&row, "receipt_reused",
                                s->receipt_reused);
        if (s->has_receipt)
            za_push_hex(&row, "build_receipt_id", s->receipt_id);
        if (s->rule[0]) {
            (void)json_push_kv_str(&row, "rule", s->rule);
            (void)json_push_kv_str(&row, "detail", s->detail);
        }
        (void)json_push_back(&steps, &row);
        json_free(&row);
    }

    if (!r.ok) {
        /* The per-step rows explain WHERE it stopped; the failure body
         * explains why. Nothing was installed past the failing step. */
        za_fail(reply, report.rule[0] ? report.rule : "commit-failed",
                r.message, command);
        json_free(&steps);
        return;
    }

    za_push_hex(&reply->data, "plan_id", report.plan_id);
    (void)json_push_kv_bool(&reply->data, "installed", report.installed);
    za_push_hex(&reply->data, "active_root", report.active_root);
    (void)json_push_kv_bool(&reply->data, "had_previous",
                            report.had_previous);
    if (report.had_previous)
        za_push_hex(&reply->data, "previous_root", report.previous_root);
    (void)json_push_kv_int(&reply->data, "step_count",
                           (int64_t)report.step_count);
    bool windowed = za_push_steps_window(request, &steps, reply, command);
    json_free(&steps);
    if (!windowed)
        return;

    /* What a PERSON can now run. The receipt that travels with the active
     * install names every output; the ones under bin/ are the executables
     * the recipe declared as programs. `programs` is ALWAYS present — an
     * empty array is the honest answer for a library-only package, and is
     * not the same as never having looked, which is why an unreadable
     * receipt is reported as `programs_rule` instead of a silent zero. */
    struct package_lifecycle_programs programs;
    struct zcl_result pr = package_lifecycle_installed_programs(
        datadir, report.active_root, &programs);
    struct json_value program_rows;
    json_init(&program_rows);
    json_set_array(&program_rows);
    char first_program[PACKAGE_LIFECYCLE_INSTALL_DIR_MAX +
                       VCS_PACKAGE_BUILD_PATH_MAX + 2u];
    first_program[0] = '\0';
    size_t rendered = 0;
    for (size_t i = 0; pr.ok && i < programs.count; i++) {
        char absolute[PACKAGE_LIFECYCLE_INSTALL_DIR_MAX +
                      VCS_PACKAGE_BUILD_PATH_MAX + 2u];
        int n = snprintf(absolute, sizeof(absolute), "%s/%s",
                         programs.install_dir, programs.output[i]);
        if (n <= 0 || (size_t)n >= sizeof(absolute))
            continue;
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "output", programs.output[i]);
        (void)json_push_kv_str(&row, "path", absolute);
        (void)json_push_back(&program_rows, &row);
        json_free(&row);
        if (!first_program[0])
            (void)snprintf(first_program, sizeof(first_program), "%s",
                           absolute);
        rendered++;
    }
    (void)json_push_kv(&reply->data, "programs", &program_rows);
    json_free(&program_rows);
    (void)json_push_kv_int(&reply->data, "program_count", (int64_t)rendered);
    if (!pr.ok)
        (void)json_push_kv_str(&reply->data, "programs_rule", pr.message);
    if (first_program[0]) {
        char next_action[sizeof(first_program) + 8u];
        (void)snprintf(next_action, sizeof(next_action), "run %s",
                       first_program);
        (void)json_push_kv_str(&reply->data, "next_action", next_action);
    }

    (void)json_push_kv_str(
        &reply->data, "note",
        "the install lands under <datadir>/zcode/installed/<root>: a static "
        "archive and public headers for code that links this package, plus "
        "an executable under bin/ for every program the recipe declares "
        "(`programs` names them, with the exact path to run). The node "
        "itself never loads or runs any of it. The previous generation "
        "stays on disk, so 'zcode package rollback' is immediate");
}

/* ── zcode package rollback ─────────────────────────────────────────── */

void zcl_native_handle_zcode_package_rollback(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *command = "zcode.package.rollback";
    const char *datadir = za_datadir(request, reply, command);
    if (!datadir)
        return;
    /* `name` is OPTIONAL: with no name this goes back one step on whichever
     * package the user most recently changed. Going back must not require
     * knowing an identifier — the caller is here because something broke. */
    const char *name = za_input_str(request->input, "name");

    struct package_lifecycle_rollback_report report;
    struct zcl_result r = package_lifecycle_rollback(datadir, name,
                                                     za_now(request),
                                                     &report);
    if (!r.ok) {
        za_fail(reply, report.rule[0] ? report.rule : "rollback-failed",
                r.message, command);
        return;
    }
    (void)json_push_kv_str(&reply->data, "name", report.name);
    (void)json_push_kv_bool(&reply->data, "selected_by_default",
                            report.selected_by_default);
    za_push_hex(&reply->data, "from_root", report.from_root);
    za_push_hex(&reply->data, "to_root", report.to_root);
    (void)json_push_kv_int(&reply->data, "generation_count",
                           (int64_t)report.generation_count);
    (void)json_push_kv_str(
        &reply->data, "note",
        "rollback appends a new generation naming the older root — history "
        "is never rewritten and both installs remain on disk. to_root is the "
        "exact 32-byte identity now active, not 'roughly the previous "
        "build'");
}

/* ── zcode package reproduce ────────────────────────────────────────── */

void zcl_native_handle_zcode_package_reproduce(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *command = "zcode.package.reproduce";
    const char *datadir = za_datadir(request, reply, command);
    if (!datadir)
        return;
    const char *name_or_root = za_input_str(request->input, "name_or_root");
    if (!name_or_root || !name_or_root[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_NAME_OR_ROOT",
                               "normalize", false, false,
                               "name_or_root is required (a 64-hex package "
                               "root, publisher/package, or name@semver)",
                               command);
        return;
    }

    /* Optional fast_cache: a LOCAL fastobj compile-cache directory handed
     * to the confined candidate worker as --fast-cache=<dir>. Absent or
     * empty means the ordinary cold rebuild; the service layer drops the
     * flag, so the argv is byte-for-byte the cold one. */
    const char *fast_cache = za_input_str(request->input, "fast_cache");

    struct package_lifecycle_reproduce_report report;
    struct zcl_result r = package_lifecycle_reproduce(datadir, name_or_root,
                                                      fast_cache, &report);
    if (report.name[0])
        (void)json_push_kv_str(&reply->data, "name", report.name);
    if (report.semver[0])
        (void)json_push_kv_str(&reply->data, "semver", report.semver);
    /* The worker's cache outcome is rendered whenever a cache was handed
     * over — including refusals, where the counters honestly read zero —
     * so a cache that was asked for is never silently unreported. */
    if (fast_cache && fast_cache[0]) {
        struct json_value fc;
        json_init(&fc);
        json_set_object(&fc);
        (void)json_push_kv_str(&fc, "dir", fast_cache);
        (void)json_push_kv_int(&fc, "hits",
                               (int64_t)report.fast_cache_hits);
        (void)json_push_kv_int(&fc, "misses",
                               (int64_t)report.fast_cache_misses);
        (void)json_push_kv_int(&fc, "reused_bytes",
                               (int64_t)report.fast_cache_reused_bytes);
        (void)json_push_kv_str(&fc, "admission",
                               report.fast_cache_admission[0]
                                   ? report.fast_cache_admission
                                   : "unavailable");
        (void)json_push_kv(&reply->data, "fast_cache", &fc);
        json_free(&fc);
    }
    if (!r.ok) {
        /* The named rule plus the compare verdict (when the rebuild ran)
         * explain exactly why nothing was filed. */
        (void)json_push_kv_str(
            &reply->data, "match_rule",
            vcs_reproduce_rule_string(
                (enum vcs_reproduce_rule)report.compare_rule));
        if (report.compare_detail[0])
            (void)json_push_kv_str(&reply->data, "match_detail",
                                   report.compare_detail);
        za_fail(reply, report.rule[0] ? report.rule : "reproduce-failed",
                r.message, command);
        return;
    }
    za_push_hex(&reply->data, "package_root", report.root);
    za_push_hex(&reply->data, "reference_receipt_id",
                report.reference_receipt_id);
    za_push_hex(&reply->data, "receipt_id", report.receipt_id);
    (void)json_push_kv_bool(&reply->data, "reproduced", report.matched);
    (void)json_push_kv_str(
        &reply->data, "match_rule",
        vcs_reproduce_rule_string(
            (enum vcs_reproduce_rule)report.compare_rule));
    char filed_rel[96];
    char id_hex[65];
    zcl_hex_encode(report.receipt_id, 32, id_hex);
    (void)snprintf(filed_rel, sizeof(filed_rel), "receipts/%s", id_hex);
    (void)json_push_kv_str(&reply->data, "filed_receipt", filed_rel);
    (void)json_push_kv_bool(&reply->data, "filed", report.filed);
    (void)json_push_kv_str(
        &reply->data, "note",
        "the second, distinct receipt is filed under "
        "<datadir>/zcode/receipts/; 'zcode package verify' now reports "
        "reproduced=true for this package (two distinct receipt ids, "
        "byte-identical output sets)");
}
