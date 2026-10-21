/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.claim — record this worktree's exclusive interest in a
 *          set of files as one ledger line beside the shared object store, so
 *          two lanes on one checkout cannot silently edit the same file.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. Several agents work one Z23 checkout at once through linked
 * worktrees. They share an object store, a stash stack and a filesystem; the
 * only thing they do not share is a record of who is editing what. This is
 * that record, and it lives where every worktree can see it.
 *
 * INPUT (zcl.agent_claim_input.v1)
 *   cwd      optional string. Directory to run Git in. Default: the process
 *            working directory.
 *   story    string, non-empty. What the claim is FOR. May be omitted only
 *            when release is true.
 *   files    array of path strings, non-empty unless release is true. Each
 *            path is relative to the worktree root and is normalized
 *            lexically (empty and "." segments collapse, ".." resolves)
 *            before any compare or record, so `a/../x`, `./x` and `x/` all
 *            name `x`. A path that is empty, absolute, not a string, or
 *            climbs above the root is refused: ok=false, status
 *            "CLAIM_PATH_REFUSED", with a message naming the path.
 *            May be omitted only when release is true; supplied files must
 *            still be an array, but release ignores its contents.
 *   release  optional bool, default false.
 *   retire_worktree optional exact ASCII absolute path. Archive one legacy
 *            row only after its owner is missing and unregistered. Files must
 *            be empty; release cannot be combined. No lease is retired.
 *
 * LEDGER. <git_common_dir>/z23-agent-claims.jsonl — resolve the directory
 * with `git rev-parse --git-common-dir` so every linked worktree on one
 * checkout writes the SAME file. One JSON object per line, newline
 * terminated, appended in claim order:
 *
 *   {"ts":"<ISO-8601 UTC>","worktree":"<toplevel>","branch":"<branch>",
 *    "story":"<story>","files":["<path>", ...]}
 *
 *   ts        ISO-8601 UTC, e.g. 2026-09-04T18:22:07Z
 *   worktree  `git rev-parse --show-toplevel`
 *   branch    `git rev-parse --abbrev-ref HEAD`, "" when detached
 *
 * SEMANTICS. New claims are 15-minute leases. Repeating the same claim from
 * the same worktree renews it. Expired rows are ignored for overlap and
 * removed by the next successful claim. Rows without a valid expires_unix
 * are legacy claims and remain live until their owner releases them or an
 * explicit orphan retirement independently verifies their missing owner.
 *   - A claim whose files intersect a live claim from a DIFFERENT worktree is
 *     refused: ok=false, status "CLAIM_OVERLAP", plus
 *     conflicts:[{file, worktree, story, claimed_at, branch}], one entry per
 *     offending file, plus ledger location. Missing historical metadata is
 *     empty; age alone never reclaims a legacy claim.
 *     Nothing is written on overlap refusal.
 *   - A claim from the SAME worktree REPLACES that worktree's own line, so
 *     re-claiming is idempotent and never overlaps itself.
 *   - release=true removes every line whose worktree is this one and reports
 *     released (count). `files` may be empty and `story` is not required to
 *     match anything.
 *   - The rewrite must be whole-file: read every line, drop the ones being
 *     replaced or released, append the new line, write the file back. A
 *     ledger that cannot be read whole is ok=false "CLAIM_LEDGER_UNREADABLE"
 *     and one past DVC_LEDGER_MAX_ROWS rows is "CLAIM_LEDGER_TOO_LARGE";
 *     neither is ever rewritten from a partial read.
 *
 * OUTPUT (zcl.agent_claim.v1) on ok=true
 *   leaf     "dev.agent.claim"
 *   claimed  array of the file paths now claimed by this worktree (empty on
 *            a release)
 *   ledger   absolute path of the ledger file
 *   live     number of live claim lines in the ledger after the write
 *   expires_unix Unix expiry of a new claim; renew before this time
 *   expired_reclaimed number of expired foreign rows removed by a claim
 *   released number of lines removed, present on a release
 *
 * FAILURE. A missing or empty `story`, or an empty `files` when release is
 * false, is ok=false, status "BAD_INPUT", with a message naming which one.
 * Any Git invocation that does not exit 0 is ok=false, status "GIT_FAILED",
 * with a message naming the failing argv.
 *
 * PROCESS RULE. Run Git only through zcl_spawn_capture() from util/spawn.h.
 * popen(), system() and a shell command string are forbidden and gated.
 *
 * Implement this file only; the test tests/harness/src/test_devagent_claim.c
 * is the acceptance bar and must not be edited.
 */

#include "command/native_command.h"
#include "base/safe_alloc.h"
#include "base/utc_tm.h"
#include "crypto/sha256.h"

#include "json/json.h"
#include "zutf8/zutf8.h"
#include "platform/clock.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "util/file_io.h"
#include "util/spawn.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <sys/stat.h>
#endif

#define DVC_LEAF "dev.agent.claim"
#define DVC_LEDGER_NAME "z23-agent-claims.jsonl"
#define DVC_LINE_CAP 8192
#define DVC_PATH_CAP 1024
#define DVC_LEDGER_MAX_ROWS 4096
#define DVC_LEDGER_MAX_BYTES ((size_t)DVC_LEDGER_MAX_ROWS * DVC_LINE_CAP)
#define DVC_LEASE_SECONDS 900

/* ── git via the only allowed rail ──────────────────────────────────────── */

static bool dvc_git(const char *cwd, const char *const args[],
                    char *out, size_t cap, char *why, size_t whycap)
{
    const char *argv[24];
    size_t n = 0;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = cwd;
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return false;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    out[0] = '\0';
    int rc = zcl_spawn_capture(argv, out, cap, 30000);
    if (rc != 0) {
        size_t used = 0;
        for (size_t i = 0; argv[i] && used + 2 < whycap; i++)
            used += (size_t)snprintf(why + used, whycap - used, "%s%s",
                                     i ? " " : "", argv[i]);
        return false;
    }
    /* Trim the trailing newline git appends. */
    size_t len = strlen(out);
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r'))
        out[--len] = '\0';
    return true;
}

/* ── tiny JSON string escape (paths and stories are trusted-ish, but the
 *    ledger is a machine-readable format; escape the mandatory pair) ────── */

static bool dvc_json_escape(const char *in, char *out, size_t cap)
{
    if (cap == 0) return false;
    out[0] = '\0';
    if (!zutf8_validate_n(in, strlen(in)))
        return false;
    size_t used = 0;
    for (const char *p = in; *p; p++) {
        char tmp[8];
        const char *rep = NULL;
        if (*p == '"' || *p == '\\') {
            tmp[0] = '\\';
            tmp[1] = *p;
            tmp[2] = '\0';
            rep = tmp;
        } else if ((unsigned char)*p < 0x20) {
            (void)snprintf(tmp, sizeof(tmp), "\\u%04x", (unsigned)*p);
            rep = tmp;
        } else {
            tmp[0] = *p;
            tmp[1] = '\0';
            rep = tmp;
        }
        size_t rl = strlen(rep);
        if (used + rl + 1 > cap)
            return false;
        memcpy(out + used, rep, rl);
        used += rl;
    }
    out[used] = '\0';
    return true;
}

/* Extract the string value of `"key":"..."` from one ledger line. */
static bool dvc_line_str(const char *line, const char *key,
                         char *out, size_t cap)
{
    char pat[64];
    (void)snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(line, pat);
    if (!p)
        return false;
    p += strlen(pat);
    size_t used = 0;
    while (*p && *p != '"') {
        if (used + 2 > cap)
            return false;
        if (*p == '\\' && p[1]) {
            out[used++] = p[1];
            p += 2;
        } else {
            out[used++] = *p++;
        }
    }
    out[used] = '\0';
    return true;
}

/* ── path normalization ─────────────────────────────────────────────────── */

/* Drop the last segment of the `used`-byte normalized prefix in `out`. */
static size_t dvc_path_pop(const char *out, size_t used)
{
    while (used > 0 && out[used - 1] != '/')
        used--;
    return used > 0 ? used - 1 : 0;
}

/* Fold one segment of `len` bytes into the normalized prefix: skip empty
 * and ".", pop on "..", append anything else. NULL, or why it failed. */
static const char *dvc_path_step(char *out, size_t *used, size_t cap,
                                 const char *seg, size_t len)
{
    bool dot = len == 1 && seg[0] == '.';
    bool dotdot = len == 2 && seg[0] == '.' && seg[1] == '.';
    if (len == 0 || dot)
        return NULL;
    if (dotdot && *used == 0)
        return "escapes the worktree root";
    if (dotdot) {
        *used = dvc_path_pop(out, *used);
        return NULL;
    }
    if (*used + len + 2 > cap)
        return "is too long";
    if (*used > 0)
        out[(*used)++] = '/';
    memcpy(out + *used, seg, len);
    *used += len;
    return NULL;
}

/* Lexically normalize one claim path into `out`: collapse empty and "."
 * segments and resolve ".." against the worktree root, so every spelling of
 * one file compares equal. Returns NULL on success, or why the path names no
 * file inside this worktree (empty, absolute, escaping the root, too long). */
static const char *dvc_path_normalize(const char *in, char *out, size_t cap)
{
    if (!in || !in[0])
        return "is empty";
    if (in[0] == '/')
        return "is absolute";
    size_t used = 0;
    for (const char *p = in; *p;) {
        const char *slash = strchr(p, '/');
        size_t len = slash ? (size_t)(slash - p) : strlen(p);
        const char *why = dvc_path_step(out, &used, cap, p, len);
        if (why)
            return why;
        p += slash ? len + 1 : len;
    }
    out[used] = '\0';
    return used > 0 ? NULL : "names no file";
}

/* Does the files array on this ledger line contain `path`? Recorded paths
 * are normalized before the compare, so a row written before normalization
 * existed still matches every spelling of its file. */
static bool dvc_line_has_file(const char *line, const char *path)
{
    const char *p = strstr(line, "\"files\":[");
    if (!p)
        return false;
    p += strlen("\"files\":[");
    while (*p && *p != ']') {
        if (*p != '"') {
            p++;
            continue;
        }
        p++;
        char item[DVC_PATH_CAP];
        size_t used = 0;
        while (*p && *p != '"') {
            if (*p == '\\' && p[1])
                p++;
            if (used + 1 < sizeof(item))
                item[used++] = *p;
            p++;
        }
        item[used] = '\0';
        if (*p == '"')
            p++;
        char norm[DVC_PATH_CAP];
        const char *cmp =
            dvc_path_normalize(item, norm, sizeof(norm)) ? item : norm;
        if (strcmp(cmp, path) == 0)
            return true;
    }
    return false;
}

/* ── input accessors ────────────────────────────────────────────────────── */

static const char *dvc_cwd(const struct zcl_command_request *request)
{
    if (!request || !request->input)
        return ".";
    const struct json_value *v = json_get(request->input, "cwd");
    if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
        return json_get_str(v);
    return ".";
}

static bool dvc_escape_claim(const char *story, const char *worktree,
                             const char *branch, char escaped_story[1024],
                             char escaped_worktree[PATH_MAX + 8],
                             char escaped_branch[512])
{
    return dvc_json_escape(story, escaped_story, 1024) &&
           dvc_json_escape(worktree, escaped_worktree, PATH_MAX + 8) &&
           dvc_json_escape(branch, escaped_branch, 512);
}

static void dvc_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, phase, false, false,
                           message, evidence);
}

/* Normalize every requested path into `norm`, refusing the first one that
 * names no file inside the worktree. Runs before any compare or record. */
static bool dvc_normalize_files(const struct json_value *filesv,
                                struct json_value *norm,
                                struct zcl_command_reply *reply)
{
    for (size_t j = 0; j < filesv->num_children; j++) {
        const struct json_value *fv = &filesv->children[j];
        const char *path = fv->type == JSON_STR ? json_get_str(fv) : NULL;
        char out[DVC_PATH_CAP];
        const char *why = path ? dvc_path_normalize(path, out, sizeof(out))
                               : "is not a string";
        if (why) {
            char msg[192];
            (void)snprintf(msg, sizeof(msg), "claim path \"%s\" %s",
                           path ? path : "", why);
            dvc_fail(reply, "CLAIM_PATH_REFUSED", "validate", msg,
                     "claim paths are relative to the worktree root");
            return false;
        }
        struct json_value item;
        json_init(&item);
        json_set_str(&item, out);
        bool pushed = json_push_back(norm, &item);
        json_free(&item);
        if (!pushed) {
            dvc_fail(reply, "BAD_INPUT", "validate",
                     "cannot hold the normalized claim paths",
                     "input.files");
            return false;
        }
    }
    return true;
}

/* ── git facts ──────────────────────────────────────────────────────────── */

struct dvc_facts {
    char toplevel[PATH_MAX];
    char branch[256];
    char ledger[PATH_MAX + 64];
};

static bool dvc_git_step(const char *cwd, const char *const args[],
                         char *out, size_t cap, const char *message,
                         struct zcl_command_reply *reply)
{
    char why[512];
    why[0] = '\0';
    if (dvc_git(cwd, args, out, cap, why, sizeof(why)))
        return true;
    dvc_fail(reply, "GIT_FAILED", "git", message, why);
    return false;
}

static bool dvc_git_facts(const char *cwd, struct dvc_facts *facts,
                          struct zcl_command_reply *reply)
{
    static const char *const common_args[] = {"rev-parse",
                                              "--git-common-dir", NULL};
    static const char *const top_args[] = {"rev-parse", "--show-toplevel",
                                           NULL};
    static const char *const branch_args[] = {"rev-parse", "--abbrev-ref",
                                              "HEAD", NULL};
    char common[PATH_MAX];
    if (!dvc_git_step(cwd, common_args, common, sizeof(common),
                      "git rev-parse --git-common-dir failed", reply) ||
        !dvc_git_step(cwd, top_args, facts->toplevel,
                      sizeof(facts->toplevel),
                      "git rev-parse --show-toplevel failed", reply) ||
        !dvc_git_step(cwd, branch_args, facts->branch,
                      sizeof(facts->branch),
                      "git rev-parse --abbrev-ref HEAD failed", reply))
        return false;
    if (strcmp(facts->branch, "HEAD") == 0)
        facts->branch[0] = '\0';
    if (common[0] == '/')
        (void)snprintf(facts->ledger, sizeof(facts->ledger), "%s/%s", common,
                       DVC_LEDGER_NAME);
    else
        (void)snprintf(facts->ledger, sizeof(facts->ledger), "%s/%s/%s", cwd,
                       common, DVC_LEDGER_NAME);
    return true;
}

/* ── the ledger: read whole or refuse, never a partial rewrite ─────────── */

struct dvc_ledger {
    char *text;   /* the whole file, split in place at newlines */
    char **lines; /* non-empty lines, pointing into text */
    size_t n;
};

static void dvc_ledger_free(struct dvc_ledger *lg)
{
    free(lg->lines);
    free(lg->text);
    memset(lg, 0, sizeof(*lg));
}

/* Split the loaded text into non-empty lines, trimming each "\r\n". */
static bool dvc_ledger_split(struct dvc_ledger *lg, size_t len)
{
    size_t rows = 1;
    for (size_t i = 0; i < len; i++)
        rows += lg->text[i] == '\n';
    lg->lines = zcl_calloc(rows, sizeof(*lg->lines), "dvc_ledger_lines");
    if (!lg->lines)
        return false;
    for (char *p = lg->text; p && *p;) {
        char *nl = strchr(p, '\n');
        if (nl)
            *nl = '\0';
        size_t l = strlen(p);
        while (l > 0 && p[l - 1] == '\r')
            p[--l] = '\0';
        if (l > 0)
            lg->lines[lg->n++] = p;
        p = nl ? nl + 1 : NULL;
    }
    return true;
}

/* Load every ledger line. A missing ledger is an empty one. A ledger that
 * cannot be read whole, or holds more rows than the cap, is refused by name
 * so no claim or release can rewrite a truncated copy of it. */
static bool dvc_ledger_load(const char *path, struct dvc_ledger *lg,
                            struct zcl_command_reply *reply)
{
    memset(lg, 0, sizeof(*lg));
    FILE *probe = fopen(path, "rb");
    if (!probe) {
        if (errno == ENOENT)
            return true;
        dvc_fail(reply, "CLAIM_LEDGER_UNREADABLE", "ledger",
                 "the claim ledger could not be opened for reading", path);
        return false;
    }
    (void)fclose(probe);
    size_t len = 0;
    if (!zcl_read_whole_file_text(path, DVC_LEDGER_MAX_BYTES, &lg->text, &len,
                                  DVC_LEAF) ||
        !dvc_ledger_split(lg, len)) {
        dvc_ledger_free(lg);
        dvc_fail(reply, "CLAIM_LEDGER_UNREADABLE", "ledger",
                 "the claim ledger could not be read whole", path);
        return false;
    }
    if (lg->n > DVC_LEDGER_MAX_ROWS) {
        dvc_ledger_free(lg);
        dvc_fail(reply, "CLAIM_LEDGER_TOO_LARGE", "ledger",
                 "the claim ledger holds more rows than it may rewrite; "
                 "release stale claims by hand",
                 path);
        return false;
    }
    return true;
}

static bool dvc_line_is_ours(const char *line, const char *toplevel)
{
    char wt[PATH_MAX];
    return dvc_line_str(line, "worktree", wt, sizeof(wt)) &&
           strcmp(wt, toplevel) == 0;
}

/* Old rows and malformed expiry fields remain live: guessing that an owned
 * worktree is idle would permit an overlapping writer. New rows are short
 * leases; the owner renews by repeating the same claim before expiry. */
static bool dvc_line_expired(const char *line, long long now)
{
    char *end = NULL;
    const char *key = "\"expires_unix\":";
    const char *p = strstr(line, key);
    long long expiry;
    if (!p)
        return false;
    p += strlen(key);
    /* A lease is authority to drop another writer's row. Accept only the
     * positive JSON integer spelling we emit, not strtoll's +, whitespace,
     * or leading-zero extensions. Ambiguous rows keep their owner. */
    if (*p < '1' || *p > '9')
        return false;
    errno = 0;
    expiry = strtoll(p, &end, 10);
    return errno == 0 && end != p && expiry > 0 &&
           (*end == ',' || *end == '}') && !strstr(end, key) && expiry <= now;
}

static bool dvc_stage_open(const char *path, char *tmp, size_t cap,
                           struct platform_private_file *file)
{
    uint64_t nonce = 0;
    if (!rng_fill((uint8_t *)&nonce, sizeof(nonce)))
        return false;
    int n = snprintf(tmp, cap, "%s.claim-%016llx", path,
                      (unsigned long long)nonce);
    return n > 0 && (size_t)n < cap &&
           platform_private_file_create(tmp, file);
}

static bool dvc_stage_line(struct platform_private_file *file,
                           const char *line, uint64_t *offset)
{
    size_t len = strlen(line);
    if (!platform_private_file_write_at(file, line, len, *offset) ||
        !platform_private_file_write_at(file, "\n", 1, *offset + len))
        return false;
    *offset += len + 1;
    return true;
}

/* Stage the whole replacement beside the ledger. Failed writes never
 * truncate the previous claims; only the complete staged file replaces it. */
static bool dvc_ledger_write(const char *path, const struct dvc_ledger *lg,
                             const char *toplevel, const char *newline,
                             long long now, size_t *kept, size_t *released,
                             size_t *expired,
                             struct zcl_command_reply *reply)
{
    *kept = 0;
    *released = 0;
    *expired = 0;
    struct platform_private_file file;
    platform_private_file_init(&file);
    char tmp[PATH_MAX + 64];
    bool created = dvc_stage_open(path, tmp, sizeof(tmp), &file);
    bool ok = created;
    uint64_t offset = 0;
    for (size_t i = 0; ok && i < lg->n; i++) {
        if (dvc_line_is_ours(lg->lines[i], toplevel)) {
            (*released)++;
            continue;
        }
        if (newline && dvc_line_expired(lg->lines[i], now)) {
            (*expired)++;
            continue;
        }
        ok = dvc_stage_line(&file, lg->lines[i], &offset);
        (*kept)++;
    }
    if (ok && newline)
        ok = dvc_stage_line(&file, newline, &offset);
    if (ok)
        ok = platform_private_file_replace(&file, tmp, path);
    if (!ok && created)
        (void)platform_private_file_retire(&file, tmp);
    platform_private_file_close(&file);
    if (!ok) {
        char why[PATH_MAX + 32];
        (void)snprintf(why, sizeof(why), "cannot write %s", path);
        dvc_fail(reply, "GIT_FAILED", "ledger",
                 "failed to rewrite the claim ledger", why);
    }
    return ok;
}

/* ── release ────────────────────────────────────────────────────────────── */

static void dvc_release(const struct dvc_facts *facts,
                        const struct dvc_ledger *lg,
                        struct zcl_command_reply *reply)
{
    size_t kept = 0, released = 0, expired = 0;
    if (!dvc_ledger_write(facts->ledger, lg, facts->toplevel, NULL, 0, &kept,
                          &released, &expired, reply))
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DVC_LEAF);
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    (void)json_push_kv(&reply->data, "claimed", &arr);
    json_free(&arr);
    (void)json_push_kv_str(&reply->data, "ledger", facts->ledger);
    (void)json_push_kv_int(&reply->data, "live", (long long)kept);
    (void)json_push_kv_int(&reply->data, "released", (long long)released);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* Explicit retirement is separate from expiry. A missing registered checkout,
 * an inaccessible path, and every lease-bearing row retain their authority. */
static bool dvc_orphan_path_valid(const char *path)
{
    if (!path || path[0] != '/' || !path[1] || strlen(path) >= PATH_MAX)
        return false;
    char normalized[PATH_MAX];
    if (dvc_path_normalize(path + 1, normalized, sizeof(normalized)) ||
        strcmp(normalized, path + 1) != 0)
        return false;
    for (const char *p = path; *p; p++) {
        if ((unsigned char)*p < 0x20 || (unsigned char)*p >= 0x80 || *p == '\\')
            return false;
    }
    return true;
}

static int dvc_orphan_registry_relation(const char *path, const char *target)
{
    char resolved[PATH_MAX], parent[PATH_MAX];
    if (!dvc_orphan_path_valid(path) ||
        !platform_private_path_resolve(path, resolved, sizeof(resolved),
                                        parent, sizeof(parent)))
        return -1;
    const unsigned char *a = (const unsigned char *)resolved;
    const unsigned char *b = (const unsigned char *)target;
    for (; *a && *b; a++, b++) {
        unsigned char left = *a >= 'A' && *a <= 'Z' ? (unsigned char)(*a + 32) : *a;
        unsigned char right = *b >= 'A' && *b <= 'Z' ? (unsigned char)(*b + 32) : *b;
        if (left != right)
            return 0;
    }
    return *a == *b ? 1 : 0;
}

static bool dvc_orphan_absent(const char *target,
                               struct zcl_command_reply *reply)
{
#ifdef _WIN32
    dvc_fail(reply, "CLAIM_ORPHAN_UNAVAILABLE", "retire",
             "orphan retirement has not qualified Windows path absence",
             target);
    return false;
#else
    struct stat st;
    if (lstat(target, &st) != 0 && errno == ENOENT)
        return true;
    dvc_fail(reply, "CLAIM_OWNER_NOT_ABSENT", "retire",
             "the owner path exists or its absence cannot be verified",
             target);
    return false;
#endif
}

static bool dvc_orphan_unregistered(const struct dvc_facts *facts,
                                     const char *target,
                                     struct zcl_command_reply *reply)
{
    const char *argv[] = {"git", "-C", facts->toplevel, "worktree", "list",
                           "--porcelain", "-z", NULL};
    char *list = zcl_malloc(65536, "claim_retirement_worktrees");
    if (!list) {
        dvc_fail(reply, "CLAIM_REGISTRY_UNAVAILABLE", "retire",
                 "cannot allocate the exact worktree registry capture", target);
        return false;
    }
    struct zcl_spawn_binary_observation observation;
    struct zcl_result result = zcl_spawn_capture_binary(
        argv, list, 65536, 30000, &observation);
    bool ok = result.ok;
    size_t count = 0;
    for (size_t pos = 0; ok && pos < observation.output_len;) {
        const char *end = memchr(list + pos, '\0', observation.output_len - pos);
        if (!end) { ok = false; break; }
        if (strncmp(list + pos, "worktree ", 9) == 0) {
            count++;
            int relation = dvc_orphan_registry_relation(list + pos + 9, target);
            if (relation < 0) { ok = false; break; }
            if (relation > 0) {
                dvc_fail(reply, "CLAIM_OWNER_REGISTERED", "retire",
                         "registered worktrees retain their claims even when missing",
                         target);
                free(list);
                return false;
            }
        }
        pos = (size_t)(end - list) + 1;
    }
    free(list);
    if (ok && count > 0)
        return true;
    dvc_fail(reply, "CLAIM_REGISTRY_UNAVAILABLE", "retire",
             "the complete worktree registry could not be independently observed",
             target);
    return false;
}

static bool dvc_json_digit(unsigned char c)
{
    return c >= '0' && c <= '9';
}

static bool dvc_json_digits(const char *bytes, size_t len, size_t *pos)
{
    size_t start = *pos;
    while (*pos < len && dvc_json_digit((unsigned char)bytes[*pos]))
        (*pos)++;
    return *pos != start;
}

/* Supplement the shared reader's permissive numeric conversion with the
 * JSON number grammar. No conversion or range guess grants authority. */
static bool dvc_json_exponent(const char *bytes, size_t len, size_t *pos)
{
    if (*pos == len || (bytes[*pos] != 'e' && bytes[*pos] != 'E'))
        return true;
    (*pos)++;
    if (*pos < len && (bytes[*pos] == '+' || bytes[*pos] == '-'))
        (*pos)++;
    return dvc_json_digits(bytes, len, pos);
}

static bool dvc_json_number(const char *bytes, size_t len, size_t *pos)
{
    if (bytes[*pos] == '-')
        (*pos)++;
    if (*pos >= len)
        return false;
    if (bytes[*pos] == '0')
        (*pos)++;
    else if (!dvc_json_digits(bytes, len, pos))
        return false;
    if (*pos < len && bytes[*pos] == '.') {
        (*pos)++;
        if (!dvc_json_digits(bytes, len, pos))
            return false;
    }
    return dvc_json_exponent(bytes, len, pos) &&
        (*pos == len || strchr(",]} \t\r\n", bytes[*pos]) != NULL);
}

static bool dvc_json_string(const char *bytes, size_t len, size_t *pos)
{
    (*pos)++;
    while (*pos < len) {
        unsigned char c = (unsigned char)bytes[(*pos)++];
        if (c == '"')
            return true;
        if (c < 0x20)
            return false;
        if (c == '\\') {
            if (*pos == len || !bytes[*pos] ||
                !strchr("\"\\/bfnrt", bytes[(*pos)++]))
                return false;
        }
    }
    return false;
}

/* Validate raw bytes before C-string key/owner comparisons. Unicode escapes
 * are conservatively refused because the shared reader substitutes them. */
static bool dvc_json_lexical(const char *bytes, size_t len)
{
    for (size_t pos = 0; pos < len;) {
        unsigned char c = (unsigned char)bytes[pos];
        if (c == '"') {
            if (!dvc_json_string(bytes, len, &pos))
                return false;
        } else if (c == '-' || dvc_json_digit(c)) {
            if (!dvc_json_number(bytes, len, &pos))
                return false;
        } else {
            if (c == 0 || (c < 0x20 && !strchr(" \t\r\n", c)))
                return false;
            pos++;
        }
    }
    return true;
}

/* Read the row as JSON rather than guessing an escaped path. Ambiguous keys,
 * Unicode substitution and malformed rows never authorize removal. */
static bool dvc_orphan_row(const char *bytes, size_t len, const char *target,
                            bool *selected)
{
    struct json_value row;
    json_init(&row);
    *selected = false;
    if (!dvc_json_lexical(bytes, len) ||
        !json_read(&row, bytes, len) || row.type != JSON_OBJ) {
        json_free(&row);
        return false;
    }
    size_t owner_keys = 0;
    const char *owner = NULL;
    for (size_t i = 0; i < row.num_children; i++) {
        if (strcmp(row.keys[i], "worktree") == 0) {
            owner_keys++;
            owner = json_get_str(&row.children[i]);
        }
    }
    bool ok = owner_keys == 1 && owner;
    if (ok && strcmp(owner, target) == 0) {
        /* No expiry spelling, including malformed expiry, may be retired. */
        ok = json_get(&row, "expires_unix") == NULL;
        *selected = ok;
    }
    json_free(&row);
    return ok;
}

struct dvc_retirement {
    struct platform_private_file ledger;
    struct platform_private_file evidence;
    char ledger_stage[PATH_MAX + 64];
    char evidence_path[PATH_MAX + 64];
    uint64_t kept_bytes;
    uint64_t retired_bytes;
    size_t retired;
    struct sha256_ctx hash;
};

static bool dvc_orphan_stage(const struct dvc_facts *facts,
                              struct dvc_retirement *stage)
{
    char evidence_base[PATH_MAX + 64];
    memset(stage, 0, sizeof(*stage));
    platform_private_file_init(&stage->ledger);
    platform_private_file_init(&stage->evidence);
    sha256_init(&stage->hash);
    int n = snprintf(evidence_base, sizeof(evidence_base), "%s.retired",
                       facts->ledger);
    return n > 0 && (size_t)n < sizeof(evidence_base) &&
        dvc_stage_open(facts->ledger, stage->ledger_stage,
                        sizeof(stage->ledger_stage), &stage->ledger) &&
        dvc_stage_open(evidence_base, stage->evidence_path,
                        sizeof(stage->evidence_path), &stage->evidence);
}

static void dvc_orphan_close(struct dvc_retirement *stage, bool committed)
{
    if (!committed && stage->ledger_stage[0])
        (void)platform_private_file_retire(&stage->ledger, stage->ledger_stage);
    if (!committed && stage->evidence_path[0])
        (void)platform_private_file_retire(&stage->evidence, stage->evidence_path);
    platform_private_file_close(&stage->ledger);
    platform_private_file_close(&stage->evidence);
}

static bool dvc_orphan_copy_row(struct dvc_retirement *stage,
                                 const char *bytes, size_t len,
                                 const char *target)
{
    bool selected = false;
    /* Native claim rows never encode Unicode paths. The JSON reader replaces
     * Unicode escapes, so retain the whole ledger on any ambiguous encoding. */
    for (size_t i = 0; i + 1 < len; i++)
        if (bytes[i] == '\\' && bytes[i + 1] == 'u')
            return false;
    size_t whitespace = 0;
    while (whitespace < len && (bytes[whitespace] == ' ' ||
           bytes[whitespace] == '\t' || bytes[whitespace] == '\r' ||
           bytes[whitespace] == '\n'))
        whitespace++;
    if (whitespace != len && !dvc_orphan_row(bytes, len, target, &selected))
        return false;
    struct platform_private_file *file = selected ? &stage->evidence : &stage->ledger;
    uint64_t *offset = selected ? &stage->retired_bytes : &stage->kept_bytes;
    if (!platform_private_file_write_at(file, bytes, len, *offset))
        return false;
    *offset += len;
    if (selected) {
        stage->retired++;
        sha256_write(&stage->hash, (const unsigned char *)bytes, len);
    }
    return true;
}

static bool dvc_orphan_copy(struct dvc_retirement *stage, const char *raw,
                             size_t len, const char *target)
{
    for (size_t pos = 0; pos < len;) {
        const char *end = memchr(raw + pos, '\n', len - pos);
        size_t bytes = end ? (size_t)(end - raw - pos) + 1 : len - pos;
        if (bytes > DVC_LINE_CAP ||
            !dvc_orphan_copy_row(stage, raw + pos, bytes, target))
            return false;
        pos += bytes;
    }
    return stage->retired == 1;
}

static bool dvc_orphan_unchanged(const char *path, const char *before, size_t len)
{
    char *after = NULL;
    size_t size = 0;
    bool ok = zcl_read_whole_file_text(path, DVC_LEDGER_MAX_BYTES,
                                       &after, &size, DVC_LEAF);
    ok = ok && size == len && memcmp(before, after, len) == 0;
    free(after);
    return ok;
}

static bool dvc_orphan_parent_flush(const struct dvc_facts *facts)
{
    char parent[PATH_MAX + 64];
    (void)snprintf(parent, sizeof(parent), "%s", facts->ledger);
    char *slash = strrchr(parent, '/');
    if (!slash)
        return false;
    *slash = '\0';
    return platform_private_parent_flush(parent);
}

static void dvc_orphan_result(const struct dvc_facts *facts,
                                const struct dvc_ledger *lg,
                                const char *target,
                                struct dvc_retirement *stage,
                                struct zcl_command_reply *reply)
{
    unsigned char digest[32];
    char hex[65];
    sha256_finalize(&stage->hash, digest);
    for (size_t i = 0; i < sizeof(digest); i++)
        (void)snprintf(hex + i * 2, 3, "%02x", digest[i]);
    (void)json_push_kv_str(&reply->data, "leaf", DVC_LEAF);
    (void)json_push_kv_str(&reply->data, "ledger", facts->ledger);
    (void)json_push_kv_str(&reply->data, "retired_worktree", target);
    (void)json_push_kv_int(&reply->data, "retired", (long long)stage->retired);
    (void)json_push_kv_int(&reply->data, "live", (long long)(lg->n - stage->retired));
    (void)json_push_kv_str(&reply->data, "evidence_path", stage->evidence_path);
    (void)json_push_kv_str(&reply->data, "evidence_sha256", hex);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static bool dvc_orphan_target_valid(const char *target,
                                     struct zcl_command_reply *reply)
{
    char resolved[PATH_MAX], parent[PATH_MAX];
    if (!dvc_orphan_path_valid(target) ||
        !platform_private_path_resolve(target, resolved, sizeof(resolved),
                                        parent, sizeof(parent)) ||
        strcmp(resolved, target) != 0) {
        dvc_fail(reply, "CLAIM_ORPHAN_PATH_REFUSED", "retire",
                 "retire_worktree requires an exact ASCII path with a real canonical parent",
                 target);
        return false;
    }
    return true;
}

static bool dvc_orphan_commit(const struct dvc_facts *facts,
                               const struct dvc_ledger *lg, const char *target,
                               struct dvc_retirement *stage,
                               const char *raw, size_t len,
                               struct zcl_command_reply *reply)
{
    if (!dvc_orphan_absent(target, reply) ||
        !dvc_orphan_unregistered(facts, target, reply))
        return false;
    if (!platform_private_file_flush(&stage->evidence) ||
        !dvc_orphan_parent_flush(facts) ||
        !dvc_orphan_unchanged(facts->ledger, raw, len) ||
        !platform_private_file_replace(&stage->ledger, stage->ledger_stage,
                                        facts->ledger)) {
        dvc_fail(reply, "CLAIM_RETIREMENT_WRITE_FAILED", "retire",
                 "the archived retirement could not replace the claim ledger",
                 facts->ledger);
        return false;
    }
    if (dvc_orphan_parent_flush(facts)) {
        dvc_orphan_result(facts, lg, target, stage, reply);
    } else {
        dvc_fail(reply, "CLAIM_RETIREMENT_WRITE_FAILED", "retire",
                 "retirement applied but its persistence barrier failed",
                 stage->evidence_path);
        reply->error.mutated = true;
    }
    return true; /* preserve evidence after replacement, including barrier failure */
}

static void dvc_retire_orphan(const struct dvc_facts *facts,
                               const struct dvc_ledger *lg, const char *target,
                               struct zcl_command_reply *reply)
{
    if (!dvc_orphan_target_valid(target, reply))
        return;
    if (!dvc_orphan_absent(target, reply) ||
        !dvc_orphan_unregistered(facts, target, reply))
        return;
    char *raw = NULL;
    size_t len = 0;
    if (!zcl_read_whole_file_text(facts->ledger, DVC_LEDGER_MAX_BYTES,
                                  &raw, &len, DVC_LEAF)) {
        dvc_fail(reply, "CLAIM_LEDGER_UNREADABLE", "retire",
                 "cannot preserve the complete original claim bytes", facts->ledger);
        return;
    }
    struct dvc_retirement stage;
    bool committed = false;
    bool ok = dvc_orphan_stage(facts, &stage) &&
        dvc_orphan_copy(&stage, raw, len, target);
    if (!ok) {
        dvc_fail(reply, "CLAIM_ORPHAN_REFUSED", "retire",
                 "no unambiguous legacy-only owner rows can be durably archived",
                 target);
    } else {
        committed = dvc_orphan_commit(facts, lg, target, &stage, raw, len, reply);
    }
    dvc_orphan_close(&stage, committed);
    free(raw);
}

/* ── claim ──────────────────────────────────────────────────────────────── */

/* Append one conflict entry per requested file that this foreign line
 * already holds. */
static size_t dvc_line_conflicts(const char *line, const char *wt,
                                 const struct json_value *norm,
                                 struct json_value *conflicts)
{
    char lstory[512];
    char claimed_at[40] = "";
    char branch[256] = "";
    lstory[0] = '\0';
    (void)dvc_line_str(line, "story", lstory, sizeof(lstory));
    if (!dvc_line_str(line, "ts", claimed_at, sizeof(claimed_at)))
        claimed_at[0] = '\0';
    if (!dvc_line_str(line, "branch", branch, sizeof(branch)))
        branch[0] = '\0';
    size_t n = 0;
    for (size_t j = 0; j < norm->num_children; j++) {
        const char *path = json_get_str(&norm->children[j]);
        if (!path || !dvc_line_has_file(line, path))
            continue;
        struct json_value entry;
        json_init(&entry);
        json_set_object(&entry);
        (void)json_push_kv_str(&entry, "file", path);
        (void)json_push_kv_str(&entry, "worktree", wt);
        (void)json_push_kv_str(&entry, "story", lstory);
        (void)json_push_kv_str(&entry, "claimed_at", claimed_at);
        (void)json_push_kv_str(&entry, "branch", branch);
        (void)json_push_back(conflicts, &entry);
        json_free(&entry);
        n++;
    }
    return n;
}

/* Refuse when any requested file is live in another worktree's line. */
static bool dvc_check_overlap(const struct dvc_facts *facts,
                              const struct dvc_ledger *lg,
                              const struct json_value *norm,
                              long long now,
                              struct zcl_command_reply *reply)
{
    struct json_value conflicts;
    json_init(&conflicts);
    json_set_array(&conflicts);
    size_t nconf = 0;
    for (size_t i = 0; i < lg->n; i++) {
        char wt[PATH_MAX];
        if (dvc_line_expired(lg->lines[i], now) ||
            !dvc_line_str(lg->lines[i], "worktree", wt, sizeof(wt)) ||
            strcmp(wt, facts->toplevel) == 0)
            continue; /* unreadable or our own line: never conflicts */
        nconf += dvc_line_conflicts(lg->lines[i], wt, norm, &conflicts);
    }
    if (nconf > 0) {
        (void)json_push_kv(&reply->data, "conflicts", &conflicts);
        (void)json_push_kv_str(&reply->data, "ledger", facts->ledger);
        dvc_fail(reply, "CLAIM_OVERLAP", "claim",
                 "files already claimed by another worktree",
                 "see conflicts in the reply data");
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action),
                       "Coordinate with the named claim owner through dev.agent.mail; "
                       "retry this claim after an authorized release or a "
                       "recorded lease expiry. Legacy claims require release.");
    }
    json_free(&conflicts);
    return nconf == 0;
}

static bool dvc_now_iso(char *ts, size_t cap)
{
    time_t now = (time_t)(clock_now_wall_ms() / 1000);
    struct tm tm_utc;
    return zcl_utc_tm(now, &tm_utc) &&
           strftime(ts, cap, "%Y-%m-%dT%H:%M:%SZ", &tm_utc) != 0;
}

/* Render this worktree's ledger line; false when it does not fit. */
static bool dvc_build_line(const char *ts, long long expires_unix,
                           const char *story,
                           const struct dvc_facts *facts,
                           const struct json_value *norm, char *line,
                           size_t cap)
{
    char esc_story[1024], esc_wt[PATH_MAX + 8], esc_br[512];
    if (!dvc_escape_claim(story, facts->toplevel, facts->branch, esc_story,
                          esc_wt, esc_br))
        return false;
    int w = snprintf(line, cap,
                     "{\"ts\":\"%s\",\"expires_unix\":%lld,\"worktree\":\"%s\",\"branch\":\"%s\","
                     "\"story\":\"%s\",\"files\":[",
                     ts, expires_unix, esc_wt, esc_br, esc_story);
    if (w < 0 || (size_t)w >= cap)
        return false;
    size_t used = (size_t)w;
    for (size_t j = 0; j < norm->num_children; j++) {
        char esc_path[DVC_PATH_CAP * 2];
        if (!dvc_json_escape(json_get_str(&norm->children[j]), esc_path,
                             sizeof(esc_path)))
            return false;
        w = snprintf(line + used, cap - used, "%s\"%s\"", j ? "," : "",
                     esc_path);
        if (w < 0 || (size_t)w >= cap - used)
            return false;
        used += (size_t)w;
    }
    w = snprintf(line + used, cap - used, "]}");
    return w >= 0 && (size_t)w < cap - used;
}

static void dvc_claim(const struct dvc_facts *facts,
                      const struct dvc_ledger *lg, const char *story,
                      const struct json_value *norm,
                      struct zcl_command_reply *reply)
{
    uint64_t now_ms = clock_now_wall_ms();
    if (now_ms / 1000 > (uint64_t)(LLONG_MAX - DVC_LEASE_SECONDS)) {
        dvc_fail(reply, "CLOCK_UNAVAILABLE", "claim",
                 "cannot bound the claim lease against the wall clock",
                 "retry after the local clock is available");
        return;
    }
    long long now = (long long)(now_ms / 1000);
    long long expires_unix = now + DVC_LEASE_SECONDS;
    if (!dvc_check_overlap(facts, lg, norm, now, reply))
        return; /* nothing is written on refusal */
    char ts[40];
    if (!dvc_now_iso(ts, sizeof(ts))) {
        dvc_fail(reply, "CLOCK_UNAVAILABLE", "claim",
                 "cannot format the current UTC timestamp",
                 "retry after the local clock is available");
        return;
    }
    char newline[DVC_LINE_CAP];
    if (!dvc_build_line(ts, expires_unix, story, facts, norm, newline,
                        sizeof(newline))) {
        dvc_fail(reply, "BAD_INPUT", "escape",
                 "claim text is invalid UTF-8 or exceeds the ledger budget",
                 "use valid UTF-8 within the ledger line budget");
        return;
    }
    size_t kept = 0, replaced = 0, expired = 0;
    if (!dvc_ledger_write(facts->ledger, lg, facts->toplevel, newline, now,
                          &kept, &replaced, &expired, reply))
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DVC_LEAF);
    (void)json_push_kv(&reply->data, "claimed", norm);
    (void)json_push_kv_str(&reply->data, "ledger", facts->ledger);
    (void)json_push_kv_int(&reply->data, "live", (long long)kept + 1);
    (void)json_push_kv_int(&reply->data, "expires_unix", expires_unix);
    (void)json_push_kv_int(&reply->data, "expired_reclaimed", (long long)expired);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static bool dvc_lock(const char *ledger, struct platform_private_file *lock,
                      struct zcl_command_reply *reply)
{
    char path[PATH_MAX + 16];
    int n = snprintf(path, sizeof(path), "%s.lock", ledger);
    if (n > 0 && (size_t)n < sizeof(path) &&
        platform_private_file_open_locked_create(path, lock))
        return true;
    dvc_fail(reply, "CLAIM_LOCK_UNAVAILABLE", "ledger",
             "cannot acquire the claim ledger lock", ledger);
    (void)snprintf(reply->error.next_action,
                   sizeof(reply->error.next_action),
                   "Retry the whole claim or release after the current writer "
                   "finishes; if this persists, inspect lock-file access. "
                   "Do not remove a live lock file.");
    return false;
}

static void dvc_run(const char *cwd, const char *story, bool release,
                    const char *retire,
                    const struct json_value *norm,
                    struct zcl_command_reply *reply)
{
    struct dvc_facts facts;
    struct dvc_ledger lg;
    if (!dvc_git_facts(cwd, &facts, reply))
        return;
    struct platform_private_file lock;
    platform_private_file_init(&lock);
    if (dvc_lock(facts.ledger, &lock, reply) &&
        dvc_ledger_load(facts.ledger, &lg, reply)) {
        if (retire)
            dvc_retire_orphan(&facts, &lg, retire, reply);
        else if (release)
            dvc_release(&facts, &lg, reply);
        else
            dvc_claim(&facts, &lg, story, norm, reply);
        dvc_ledger_free(&lg);
    }
    /* Persistent sidecar: unlinking it would split the lock identity. */
    platform_private_file_close(&lock);
}

/* Acquisition/retirement require story and files. Release may omit them,
 * but supplied fields retain their validation before any ledger write. */
static bool
dvc_validate(const struct json_value *input, bool allow_empty, bool release,
             const char **story, const struct json_value **files,
             struct zcl_command_reply *reply)
{
    const struct json_value *storyv = json_get(input, "story");
    *story = storyv && storyv->type == JSON_STR ? json_get_str(storyv) : NULL;
    if ((!storyv && !release) || (storyv && (!*story || !(*story)[0]))) {
        dvc_fail(reply, "BAD_INPUT", "validate",
                 "story is required and must be non-empty",
                 "input.story missing or empty");
        return false;
    }
    const struct json_value *filesv = json_get(input, "files");
    if ((!filesv && !release) || (filesv && filesv->type != JSON_ARR)) {
        dvc_fail(reply, "BAD_INPUT", "validate",
                 "files is required and must be an array",
                 "input.files missing or wrong type");
        return false;
    }
    if (!allow_empty && filesv->num_children == 0) {
        dvc_fail(reply, "BAD_INPUT", "validate",
                 "files must be non-empty unless release is true",
                 "input.files was empty");
        return false;
    }
    *files = filesv;
    return true;
}

static bool dvc_retire_input(const struct json_value *input, bool release,
                              const char **retire,
                              struct zcl_command_reply *reply)
{
    const struct json_value *value = json_get(input, "retire_worktree");
    *retire = value ? json_get_str(value) : NULL;
    if (value && (!*retire || !(*retire)[0] || release)) {
        dvc_fail(reply, "BAD_INPUT", "validate",
                 "retire_worktree must be a non-empty path and cannot combine with release",
                 "input.retire_worktree");
        return false;
    }
    return true;
}

void zcl_native_handle_dev_agent_claim(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    if (!request || !request->input) {
        dvc_fail(reply, "BAD_INPUT", "validate",
                 "dev.agent.claim requires an input document",
                 "request.input was missing");
        return;
    }
    const struct json_value *releasev = json_get(request->input, "release");
    const bool release = releasev && releasev->type == JSON_BOOL &&
                         json_get_bool(releasev);
    const char *retire = NULL;
    if (!dvc_retire_input(request->input, release, &retire, reply))
        return;
    const char *story = NULL;
    const struct json_value *filesv = NULL;
    if (!dvc_validate(request->input, release || retire, release, &story,
                      &filesv, reply))
        return;
    if (retire && filesv->num_children != 0) {
        dvc_fail(reply, "BAD_INPUT", "validate",
                 "retire_worktree cannot combine retirement with a file claim",
                 "input.files must be empty for retirement");
        return;
    }

    /* Normalize before any compare or record; a release ignores files. */
    struct json_value norm;
    json_init(&norm);
    json_set_array(&norm);
    if (release || retire || dvc_normalize_files(filesv, &norm, reply))
        dvc_run(dvc_cwd(request), story, release, retire, &norm, reply);
    json_free(&norm);
}
