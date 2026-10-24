/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet.receipt.append` leaf: appends one JSON line saying how
 *          a producer target of the report card ended, so `fleet goals` can
 *          grade C1 C2 C4 C5 and C7 from the newest line like C3.
 *
 * WHAT IT DECIDES. Nothing. The producer target decided pass, fail or skip;
 * this leaf records that and the running binary's source id, the host and
 * the clock. It writes only <state>/zclassic23-receipts/<item>.jsonl,
 * created with the directory 0700, one O_APPEND write per line. */

#include "native_fleet_goals.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "util/clientversion.h"
#include "util/file_tree_ops.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FR_DETAIL_MAX 256u
#define FR_COMMIT_CHARS 12u
#define FR_LINE_MAX 4096u
#define FR_PATH_MAX 512u
#define FR_HOST_MAX 128u

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static void fr_refuse(struct zcl_command_reply *reply, const char *code,
                      const char *message, const char *evidence, bool mutated)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "receipt", false,
                           mutated, message, evidence);
}

static const char *fr_str(const struct json_value *in, const char *key)
{
    const struct json_value *v = in ? json_get(in, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static bool fr_verdict_known(const char *v)
{
    return v && (strcmp(v, "pass") == 0 || strcmp(v, "fail") == 0 ||
                 strcmp(v, "skip") == 0);
}

/* wall_s as a JSON integer or a decimal string; false when present but not a
 * whole number of seconds >= 0. *given says whether it was present. */
static bool fr_wall(const struct json_value *in, bool *given, int64_t *out)
{
    const struct json_value *v = in ? json_get(in, "wall_s") : NULL;
    char *end;
    long long n;
    *given = v != NULL;
    if (!v)
        return true;
    if (v->type == JSON_INT) {
        *out = json_get_int(v);
        return *out >= 0;
    }
    if (v->type != JSON_STR || !json_get_str(v)[0])
        return false;
    errno = 0;
    n = strtoll(json_get_str(v), &end, 10);
    if (errno != 0 || *end != '\0' || n < 0)
        return false;
    *out = n;
    return true;
}

/* At most FR_DETAIL_MAX bytes of detail, never ending inside a multi-byte
 * UTF-8 sequence. */
static void fr_detail(const char *text, char *out)
{
    size_t n = text ? strlen(text) : 0;
    if (n > FR_DETAIL_MAX) {
        n = FR_DETAIL_MAX;
        while (n > 0 && ((unsigned char)text[n] & 0xC0u) == 0x80u)
            n--;
    }
    if (n > 0)
        memcpy(out, text, n);
    out[n] = '\0';
}

static bool fr_row(struct json_value *row, int64_t ts, const char *item,
                   const char *verdict, bool has_wall, int64_t wall,
                   const char *detail)
{
    char commit[FR_COMMIT_CHARS + 1];
    char host[FR_HOST_MAX] = "";
    const char *source = zcl_build_source_id_sha256();
    (void)snprintf(commit, sizeof(commit), "%.*s", (int)FR_COMMIT_CHARS,
                   source ? source : "unknown");
#if !defined(_WIN32)
    if (gethostname(host, sizeof(host)) != 0)
        host[0] = '\0';
    host[sizeof(host) - 1] = '\0';
#endif
    json_set_object(row);
    return json_push_kv_int(row, "ts", ts) &&
           json_push_kv_str(row, "item", item) &&
           json_push_kv_str(row, "verdict", verdict) &&
           (!has_wall || json_push_kv_int(row, "wall_s", wall)) &&
           json_push_kv_str(row, "build_commit", commit) &&
           json_push_kv_str(row, "host", host) &&
           json_push_kv_str(row, "detail", detail);
}

/* One O_APPEND write of the whole line; the directory is made 0700. */
static bool fr_append(const char *path, const char *line, size_t len)
{
    char dir[FR_PATH_MAX];
    char *slash;
    ssize_t w;
    int fd;
    (void)snprintf(dir, sizeof(dir), "%s", path);
    slash = strrchr(dir, '/');
    if (!slash)
        return false;
    *slash = '\0';
    if (!zcl_mkdir_p(dir, 0700).ok)
        return false;
    fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
              0600);
    if (fd < 0)
        return false;
    w = write(fd, line, len);
    return close(fd) == 0 && w == (ssize_t)len;
}

static bool fr_inputs(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply, const char **item,
                      const char **verdict)
{
    *item = fr_str(request ? request->input : NULL, "item");
    *verdict = fr_str(request ? request->input : NULL, "verdict");
    if (!*item || !zcl_goals_receipt_target(*item)) {
        fr_refuse(reply, "RECEIPT_ITEM_UNKNOWN",
                  "item is one of C1, C2, C4, C5 or C7", "input.item", false);
        return false;
    }
    if (!fr_verdict_known(*verdict)) {
        fr_refuse(reply, "RECEIPT_VERDICT_UNKNOWN",
                  "verdict is one of pass, fail or skip", "input.verdict",
                  false);
        return false;
    }
    return true;
}

static void fr_append_run(const struct zcl_command_request *request,
                          struct zcl_command_reply *reply)
{
    const char *item, *verdict;
    char path[FR_PATH_MAX], detail[FR_DETAIL_MAX + 1], line[FR_LINE_MAX];
    struct json_value row;
    int64_t wall = 0, ts = (int64_t)platform_time_wall_time_t();
    bool has_wall = false, ok;
    size_t len;

    if (!fr_inputs(request, reply, &item, &verdict))
        return;
    if (!fr_wall(request->input, &has_wall, &wall)) {
        fr_refuse(reply, "RECEIPT_WALL_INVALID",
                  "wall_s is a whole number of seconds, 0 or more",
                  "input.wall_s", false);
        return;
    }
    fr_detail(fr_str(request->input, "detail"), detail);
    json_init(&row);
    ok = fr_row(&row, ts, item, verdict, has_wall, wall, detail);
    len = ok ? json_write(&row, line, sizeof(line) - 1) : 0;
    json_free(&row);
    if (!ok || len == 0 || len >= sizeof(line) - 1) {
        fr_refuse(reply, "RECEIPT_ROW_FAILED", "the receipt line did not fit",
                  "row", false);
        return;
    }
    line[len++] = '\n';
    if (!zcl_goals_receipt_path(NULL, false, item, path, sizeof(path)) ||
        !fr_append(path, line, len)) {
        fr_refuse(reply, "RECEIPT_WRITE_FAILED",
                  "the receipt file could not be appended", "state", false);
        return;
    }
    ok = json_push_kv_str(&reply->data, "item", item) &&
         json_push_kv_str(&reply->data, "verdict", verdict) &&
         json_push_kv_int(&reply->data, "ts", ts) &&
         json_push_kv_str(&reply->data, "path", path);
    if (!ok) {
        fr_refuse(reply, "RECEIPT_REPLY_FAILED",
                  "the receipt was appended but the reply could not be built",
                  "reply", true);
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
    reply->error.mutated = true;
}

void zcl_native_handle_fleet_receipt_append(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_receipt_append.v1");
    fr_append_run(request, reply);
}
