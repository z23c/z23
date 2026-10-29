/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the dev.land.submit leaf entry. Over MCP (plan_first) a submit
 *          without confirm answers with a plan and queues nothing; the same
 *          call with the plan_id and confirm:true queues exactly as the CLI
 *          does. The CLI leaves plan_first false and queues at once. */

#include "command/native_command.h"
#include "command/native_dev_land_internal.h"

#include "json/json.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The plan binds every input the submit forwards plus the worktree HEAD, so
 * a moved HEAD or any changed input makes an old plan_id stale. */
static void dlp_plan_id(const struct json_value *in, const char *head,
                        char out[65])
{
    static const char tag[] = "z23.dev_land_submit.plan.v1";
    static const char *const keys[] = {"tip", "worktree", "note", "precheck"};
    static const char *const flags[] = {"qualify", "json"};
    struct sha3_256_ctx ctx;
    unsigned char d[32];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)tag, sizeof(tag));
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const char *s = json_get_str(json_get(in, keys[i]));
        sha3_256_write(&ctx, (const unsigned char *)s, strlen(s) + 1);
    }
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        unsigned char b = json_get_bool(json_get(in, flags[i])) ? 1 : 0;
        sha3_256_write(&ctx, &b, 1);
    }
    sha3_256_write(&ctx, (const unsigned char *)head, strlen(head) + 1);
    sha3_256_finalize(&ctx, d);
    for (size_t i = 0; i < 32; i++)
        (void)snprintf(out + 2 * i, 3, "%02x", d[i]);
}

/* One git line from the worktree, trailing newline stripped. */
static bool dlp_git_line(const char *wt, const char *const *args, char *out,
                         size_t cap)
{
    if (dl_git(wt, args, out, cap, DL_GIT_TIMEOUT_MS) != 0)
        return false;
    out[strcspn(out, "\r\n")] = '\0';
    return out[0] != '\0';
}

static void dlp_report(const struct json_value *in, const char *wt,
                       const char *head, const char *plan_id,
                       struct zcl_command_reply *reply)
{
    const char *branch_args[] = {"rev-parse", "--abbrev-ref", "HEAD", NULL};
    const char *ahead_args[] = {"rev-list", "--count", "origin/main..HEAD",
                                NULL};
    char branch[256] = "", ahead[32] = "";
    const char *precheck = json_get_str(json_get(in, "precheck"));
    (void)dlp_git_line(wt, branch_args, branch, sizeof(branch));
    (void)json_push_kv_str(&reply->data, "plan_id", plan_id);
    (void)json_push_kv_str(&reply->data, "worktree", wt);
    (void)json_push_kv_str(&reply->data, "branch", branch);
    (void)json_push_kv_str(&reply->data, "head", head);
    if (dlp_git_line(wt, ahead_args, ahead, sizeof(ahead)))
        (void)json_push_kv_int(&reply->data, "commits_ahead",
                               (int64_t)strtoll(ahead, NULL, 10));
    (void)json_push_kv_str(&reply->data, "precheck",
                           precheck[0] ? precheck : "run");
    (void)json_push_kv_bool(&reply->data, "qualify",
                            json_get_bool(json_get(in, "qualify")));
    (void)json_push_kv_bool(&reply->data, "mutated", false);
    (void)json_push_kv_str(&reply->data, "next",
        "repeat the same call with this plan_id and confirm:true to queue");
}

/* MCP only. Returns true when the submit may proceed. */
static bool dlp_authorised(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    const char *wt = json_get_str(json_get(in, "worktree"));
    const char *given = json_get_str(json_get(in, "plan_id"));
    const char *head_args[] = {"rev-parse", "HEAD", NULL};
    char head[80] = "", want[65];
    if (!request->context || !request->context->plan_first)
        return true;
    if (!wt[0] || !dlp_git_line(wt, head_args, head, sizeof(head))) {
        dl_fail(reply, "BAD_INPUT", "submit",
                "a planned submit needs worktree to name a git checkout",
                "input.worktree missing or has no HEAD");
        return false;
    }
    dlp_plan_id(in, head, want);
    if (!json_get_bool(json_get(in, "confirm"))) {
        if (given[0]) {
            dl_fail(reply, "CONFIRM_REQUIRED", "submit",
                    "a plan_id commits only with confirm:true",
                    "input.confirm missing");
            return false;
        }
        dlp_report(in, wt, head, want, reply);
        return false;
    }
    if (strcmp(given, want) != 0) {
        dl_fail(reply, "PLAN_MISMATCH", "submit",
                "plan_id is missing or stale for these inputs or this HEAD; "
                "request a new plan without confirm",
                "input.plan_id");
        return false;
    }
    return true;
}

/* The submit leaf. It reaches the submit path directly, never the shared verb
 * dispatch, so an `action` input cannot steer it to another verb. */
void zcl_native_handle_dev_land_submit(const struct zcl_command_request *request,
                                       struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    if (!request || !request->input) {
        dl_fail(reply, "BAD_INPUT", "route", "dev.land.submit needs input",
                "request.input was missing");
        return;
    }
    if (!dlp_authorised(request, reply))
        return;
    zcl_native_dev_land_submit_local(request, reply);
}
