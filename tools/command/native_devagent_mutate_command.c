/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.mutate — break one source line, rebuild, run one
 *          registered test group, restore, and report whether the group
 *          NOTICED. An assertion that cannot fail is invisible to every
 *          green suite; this is the one command that finds it, and it always
 *          puts the file back. */

#include "command/native_command.h"
#include "command/native_devagent.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/directory_compat.h"

#include "dev/test_group_catalog.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DVM_PATH "dev.agent.mutate"

/* A source file this command will edit. Anything larger is not a hand-written
 * translation unit and is refused rather than rewritten. */
#define DVM_SOURCE_MAX (4u * 1024u * 1024u)

/* Where the untouched bytes live between the write and the restore. Kept
 * inside the checkout's build tree so a crashed or killed run leaves durable,
 * discoverable evidence instead of a quietly corrupted source file. */
#define DVM_PENDING_DIR   "build/agent-mutate"
#define DVM_PENDING_PATH  DVM_PENDING_DIR "/pending.path"
#define DVM_PENDING_BYTES DVM_PENDING_DIR "/pending.bytes"

#define DVM_BUILD_TIMEOUT_MS 1200000
#define DVM_TEST_TIMEOUT_MS   900000

static void dvm_refuse(struct zcl_command_reply *reply,
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

static const char *dvm_str(const struct json_value *input, const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static bool dvm_bool(const struct json_value *input, const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v && json_get_bool(v);
}

static int64_t dvm_int(const struct json_value *input, const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static bool dvm_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

/* ── whole-file read/write ─────────────────────────────────────────────── */

static char *dvm_read_file(const char *path, size_t *len_out)
{
    *len_out = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        (void)fclose(f);
        return NULL;
    }
    long size = ftell(f);
    if (size < 0 || (size_t)size > DVM_SOURCE_MAX || fseek(f, 0, SEEK_SET) != 0) {
        (void)fclose(f);
        return NULL;
    }
    char *buf = zcl_malloc((size_t)size + 1, "devagent.source");
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }
    size_t read = fread(buf, 1, (size_t)size, f);
    (void)fclose(f);
    if (read != (size_t)size) {
        free(buf);
        return NULL;
    }
    buf[size] = '\0';
    *len_out = (size_t)size;
    return buf;
}

static bool dvm_write_file(const char *path, const char *bytes, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = len == 0 || fwrite(bytes, 1, len, f) == len;
    /* fclose flushes; a write that fails only at close must not report OK. */
    if (fclose(f) != 0)
        ok = false;
    return ok;
}

/* ── pending-restore slot ──────────────────────────────────────────────── */

static bool dvm_pending_present(const char *root, char *rel, size_t rel_cap)
{
    char path[PATH_MAX];
    if (!dvm_join(path, sizeof(path), root, DVM_PENDING_PATH))
        return false;
    size_t len = 0;
    char *bytes = dvm_read_file(path, &len);
    if (!bytes)
        return false;
    bytes[strcspn(bytes, "\r\n")] = '\0';
    bool ok = bytes[0] != '\0';
    if (ok && rel && rel_cap)
        (void)snprintf(rel, rel_cap, "%s", bytes);
    free(bytes);
    return ok;
}

static bool dvm_pending_arm(const char *root, const char *rel,
                            const char *bytes, size_t len)
{
    char dir[PATH_MAX], path[PATH_MAX], blob[PATH_MAX];
    if (!dvm_join(dir, sizeof(dir), root, DVM_PENDING_DIR) ||
        !dvm_join(path, sizeof(path), root, DVM_PENDING_PATH) ||
        !dvm_join(blob, sizeof(blob), root, DVM_PENDING_BYTES))
        return false;
    /* build/ already exists in any checkout that produced this binary; the
     * subdirectory is the only thing that may be missing. */
    if (!platform_directory_ensure(dir, 0755))
        return false;
    /* Bytes first, then the path marker: the marker's presence is what a
     * later run keys on, so it must never point at a blob that is not on
     * disk yet. */
    return dvm_write_file(blob, bytes, len) &&
           dvm_write_file(path, rel, strlen(rel));
}

static bool dvm_pending_restore(const char *root, char *rel, size_t rel_cap,
                                size_t *restored_bytes)
{
    *restored_bytes = 0;
    if (!dvm_pending_present(root, rel, rel_cap))
        return false;
    char blob[PATH_MAX], target[PATH_MAX], marker[PATH_MAX];
    if (!dvm_join(blob, sizeof(blob), root, DVM_PENDING_BYTES) ||
        !dvm_join(target, sizeof(target), root, rel) ||
        !dvm_join(marker, sizeof(marker), root, DVM_PENDING_PATH))
        return false;
    size_t len = 0;
    char *bytes = dvm_read_file(blob, &len);
    if (!bytes)
        return false;
    bool ok = dvm_write_file(target, bytes, len);
    free(bytes);
    if (ok) {
        *restored_bytes = len;
        /* Marker first: while it exists the slot is armed, so removing it
         * last would leave a window where the bytes are already gone. */
        (void)unlink(marker);
        (void)unlink(blob);
    }
    return ok;
}

/* ── input validation ──────────────────────────────────────────────────── */

/* A repository-relative C source path, under one of the trees this command
 * is allowed to edit. Absolute paths and `..` are refused outright: a
 * mutation check writes to the file it names, and this is the only thing
 * standing between a typo and an edit outside the checkout. */
static bool dvm_path_ok(const char *rel)
{
    if (!rel || !rel[0] || rel[0] == '/' || strlen(rel) >= 512)
        return false;
    if (strstr(rel, "..") || strchr(rel, '\\'))
        return false;
    size_t len = strlen(rel);
    bool is_c = len > 2 && strcmp(rel + len - 2, ".c") == 0;
    bool is_h = len > 2 && strcmp(rel + len - 2, ".h") == 0;
    if (!is_c && !is_h)
        return false;
    static const char *const roots[] = { "lib/", "app/", "src/", "tools/",
                                         "config/" };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (strncmp(rel, roots[i], strlen(roots[i])) == 0)
            return true;
    return false;
}

static bool dvm_group_ok(const char *group)
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

/* Byte range of 1-based line `want` in `text`, excluding its newline. */
static bool dvm_line_span(const char *text, size_t len, long long want,
                          size_t *start, size_t *end)
{
    long long line = 1;
    size_t i = 0;
    *start = 0;
    while (i < len && line < want) {
        if (text[i] == '\n')
            line++;
        i++;
    }
    if (line != want)
        return false;
    *start = i;
    while (i < len && text[i] != '\n')
        i++;
    *end = i;
    return true;
}

/* One line alone cannot reveal an enclosing block comment, so a line that
 * merely LOOKS like comment prose is refused instead of silently mutating
 * text the compiler never reads. */
static bool dvm_line_is_comment_or_blank(const char *line)
{
    while (*line == ' ' || *line == '\t')
        line++;
    if (!*line)
        return true;
    if (line[0] == '*')
        return true;
    if (line[0] == '/' && (line[1] == '/' || line[1] == '*'))
        return true;
    return false;
}

/* ── the check ─────────────────────────────────────────────────────────── */

struct dvm_stage {
    int build_rc;
    int run_rc;
    struct zcl_devagent_verdict verdict;
    bool truncated;
};

static bool dvm_stage_green(const struct dvm_stage *s)
{
    return s->build_rc == 0 && s->verdict.present && s->verdict.groups_ran > 0 &&
           s->verdict.groups_failed == 0;
}

static void dvm_push_stage(struct json_value *obj, const char *key,
                           const struct dvm_stage *s)
{
    struct json_value stage;
    json_init(&stage);
    json_set_object(&stage);
    (void)json_push_kv_int(&stage, "build_exit_code", s->build_rc);
    (void)json_push_kv_int(&stage, "runner_exit_code", s->run_rc);
    (void)json_push_kv_bool(&stage, "verdict_present", s->verdict.present);
    (void)json_push_kv_int(&stage, "groups_ran", s->verdict.groups_ran);
    (void)json_push_kv_int(&stage, "groups_failed", s->verdict.groups_failed);
    (void)json_push_kv(obj, key, &stage);
    json_free(&stage);
}

void zcl_native_handle_dev_agent_mutate(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *input = request->input;
    char root[PATH_MAX];
    if (!zcl_devagent_checkout_root(NULL, root, sizeof(root))) {
        dvm_refuse(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                   "NOT_IN_A_CHECKOUT", "resolve",
                   "no Z23 checkout root above the current directory",
                   DVM_PATH,
                   "cd into a Z23 checkout, then rerun: z23 dev agent mutate "
                   "--file=<path> --line=<n> --group=<name>");
        return;
    }

    char pending_rel[512];
    bool pending = dvm_pending_present(root, pending_rel, sizeof(pending_rel));

    if (dvm_bool(input, "restore")) {
        size_t restored = 0;
        if (!pending) {
            dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED,
                       ZCL_COMMAND_EXIT_INVALID, "NO_PENDING_MUTATION",
                       "restore",
                       "no mutation is outstanding; this checkout's sources "
                       "are as this command left them",
                       DVM_PENDING_PATH,
                       "z23 dev agent mutate --file=<path> --line=<n> "
                       "--group=<name>");
            return;
        }
        if (!dvm_pending_restore(root, pending_rel, sizeof(pending_rel),
                                 &restored)) {
            char msg[192];
            (void)snprintf(msg, sizeof(msg),
                           "could not restore %s from the pending backup",
                           pending_rel);
            dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED,
                       ZCL_COMMAND_EXIT_FAILED, "RESTORE_FAILED", "restore",
                       msg, DVM_PENDING_BYTES,
                       "cp " DVM_PENDING_BYTES " <the file named above>, then "
                       "rm " DVM_PENDING_PATH);
            return;
        }
        (void)json_push_kv_str(&reply->data, "schema",
                               "zcl.agent_mutation_check.v1");
        (void)json_push_kv_str(&reply->data, "action", "restore");
        (void)json_push_kv_str(&reply->data, "file", pending_rel);
        (void)json_push_kv_int(&reply->data, "restored_bytes",
                               (int64_t)restored);
        (void)json_push_kv_bool(&reply->data, "restored", true);
        (void)json_push_kv_str(&reply->data, "next_action",
                               "make -j\"$(getconf _NPROCESSORS_ONLN)\" "
                               "test_parallel");
        return;
    }

    if (pending) {
        char msg[192];
        (void)snprintf(msg, sizeof(msg),
                       "%s still carries an unrestored mutation from an "
                       "earlier run; refusing to mutate a second file",
                       pending_rel);
        dvm_refuse(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                   "MUTATION_NOT_RESTORED", "precondition", msg,
                   DVM_PENDING_PATH,
                   "z23 dev agent mutate --restore=true");
        return;
    }

    const char *rel = dvm_str(input, "file");
    long long line_no = dvm_int(input, "line");
    const char *group = dvm_str(input, "group");

    if (!dvm_path_ok(rel)) {
        dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "INVALID_FILE", "validate",
                   "file must be a checkout-relative .c or .h path under "
                   "lib/, app/, src/, tools/ or config/ — no absolute path "
                   "and no '..'",
                   rel ? rel : "(absent)",
                   "z23 dev agent mutate --file=lib/base/src/hex.c --line=42 "
                   "--group=hex_codec");
        return;
    }
    if (line_no <= 0) {
        dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "INVALID_LINE", "validate",
                   "line must be a positive 1-based line number", rel,
                   "z23 dev agent mutate --file=<path> --line=1 --group=<name>");
        return;
    }
    if (!dvm_group_ok(group)) {
        dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "INVALID_TEST_GROUP", "validate",
                   "group must name a registered test group", rel,
                   "z23 dev agent test --group=<substring>  (to find the "
                   "group that covers this file)");
        return;
    }
    char full[ZCL_TEST_GROUP_FULL_MAX];
    bool exact = zcl_test_group_resolve_exact(group, full);
    char selector[160];
    (void)snprintf(selector, sizeof(selector), "--%s=%s",
                   exact ? "exact" : "only", exact ? full : group);

    char abs[PATH_MAX];
    if (!dvm_join(abs, sizeof(abs), root, rel)) {
        dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "INVALID_FILE", "validate", "path too long for this host",
                   rel, "shorten the path or run from the checkout root");
        return;
    }
    size_t len = 0;
    char *original = dvm_read_file(abs, &len);
    if (!original) {
        dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "FILE_UNREADABLE", "validate",
                   "the file could not be read, or is larger than 4 MiB", rel,
                   "z23 code map  (to find the file's exact path)");
        return;
    }

    size_t start = 0, end = 0;
    if (!dvm_line_span(original, len, line_no, &start, &end)) {
        char msg[192];
        (void)snprintf(msg, sizeof(msg), "%s has no line %lld", rel, line_no);
        free(original);
        dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "LINE_OUT_OF_RANGE", "validate", msg, rel,
                   "z23 dev agent mutate --file=<path> --line=<a line that "
                   "exists> --group=<name>");
        return;
    }
    char line[4200];
    if (end - start >= sizeof(line)) {
        free(original);
        dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "LINE_TOO_LONG", "validate",
                   "the line is longer than this command will rewrite", rel,
                   "pick a shorter line to mutate");
        return;
    }
    memcpy(line, original + start, end - start);
    line[end - start] = '\0';

    if (dvm_line_is_comment_or_blank(line)) {
        free(original);
        dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "LINE_NOT_CODE", "validate",
                   "that line is blank or reads as comment text; one line "
                   "alone cannot be told apart from a block-comment interior",
                   line,
                   "pick a line carrying a comparison (==, !=, <=, >=), a "
                   "boolean connective (&&, ||), true/false, or an integer "
                   "literal");
        return;
    }

    struct zcl_devagent_mutation mutation;
    char mutated[4200];
    if (!zcl_devagent_mutate_line(line, &mutation, mutated, sizeof(mutated))) {
        free(original);
        dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "LINE_NOT_MUTABLE", "validate",
                   "no mutation rule applies to that line", line,
                   "pick a line carrying a comparison (==, !=, <=, >=), a "
                   "boolean connective (&&, ||), true/false, or an integer "
                   "literal");
        return;
    }

    /* ── baseline ──────────────────────────────────────────────────────────
     * A mutation check on a red or non-executing group proves nothing, so
     * the baseline is established BEFORE the source is touched. */
    struct dvm_stage before;
    memset(&before, 0, sizeof(before));
    before.build_rc = zcl_devagent_run_make(root, "test_parallel",
                                            DVM_BUILD_TIMEOUT_MS);
    if (before.build_rc != 0) {
        free(original);
        dvm_refuse(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                   "BASELINE_BUILD_FAILED", "baseline",
                   "the unmodified checkout does not build; nothing was "
                   "mutated",
                   rel,
                   "make -j\"$(getconf _NPROCESSORS_ONLN)\" test_parallel  "
                   "(fix the build first)");
        return;
    }
    before.run_rc = zcl_devagent_run_group(root, selector, DVM_TEST_TIMEOUT_MS,
                                           &before.verdict, &before.truncated);
    if (!dvm_stage_green(&before)) {
        char msg[192];
        (void)snprintf(msg, sizeof(msg),
                       "baseline: %s ran %lld group(s) with %lld failure(s); "
                       "a mutation check needs a green, executing baseline",
                       selector, before.verdict.groups_ran,
                       before.verdict.groups_failed);
        free(original);
        char next[192];
        (void)snprintf(next, sizeof(next),
                       "z23 dev agent test --group=%s  (see why the group is "
                       "red or gated before mutating anything)",
                       exact ? full : group);
        dvm_refuse(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                   "BASELINE_NOT_GREEN", "baseline", msg, selector, next);
        char next_input[256];
        int n = snprintf(next_input, sizeof(next_input), "{\"group\":\"%s\"}",
                         exact ? full : group);
        if (n > 0 && (size_t)n < sizeof(next_input))
            (void)zcl_command_reply_add_next(
                reply, "dev.agent.test", next_input,
                "run the group on its own and read what actually executed");
        return;
    }

    /* ── mutate ───────────────────────────────────────────────────────────
     * The untouched bytes are on disk before the edit is written, so an
     * interrupted run leaves a restorable checkout and the next invocation
     * refuses until it is restored. */
    if (!dvm_pending_arm(root, rel, original, len)) {
        free(original);
        dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                   "BACKUP_FAILED", "mutate",
                   "could not stage the original bytes; refusing to edit a "
                   "file this command could not put back",
                   DVM_PENDING_DIR,
                   "mkdir -p " DVM_PENDING_DIR " and rerun");
        return;
    }
    size_t tail = len - end;
    size_t mutated_len = start + strlen(mutated) + tail;
    char *rewritten = zcl_malloc(mutated_len + 1, "devagent.mutated");
    if (!rewritten) {
        free(original);
        dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                   "MUTATE_ALLOC_FAILED", "mutate",
                   "could not build the mutated file image", rel,
                   "z23 dev agent mutate --restore=true");
        return;
    }
    memcpy(rewritten, original, start);
    memcpy(rewritten + start, mutated, strlen(mutated));
    memcpy(rewritten + start + strlen(mutated), original + end, tail);
    rewritten[mutated_len] = '\0';
    bool written = dvm_write_file(abs, rewritten, mutated_len);
    free(rewritten);
    if (!written) {
        free(original);
        dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                   "MUTATE_WRITE_FAILED", "mutate",
                   "could not write the mutated file", rel,
                   "z23 dev agent mutate --restore=true");
        return;
    }

    struct dvm_stage after;
    memset(&after, 0, sizeof(after));
    after.build_rc = zcl_devagent_run_make(root, "test_parallel",
                                           DVM_BUILD_TIMEOUT_MS);
    const char *noticed_by = "nothing";
    bool noticed = false;
    if (after.build_rc != 0) {
        noticed = true;
        noticed_by = "compiler";
    } else {
        after.run_rc = zcl_devagent_run_group(root, selector,
                                              DVM_TEST_TIMEOUT_MS,
                                              &after.verdict, &after.truncated);
        if (after.verdict.present && after.verdict.groups_failed > 0) {
            noticed = true;
            noticed_by = "test_group";
        }
    }

    /* ── restore, unconditionally ─────────────────────────────────────── */
    bool restored = dvm_write_file(abs, original, len);
    free(original);
    char marker[PATH_MAX], blob[PATH_MAX];
    if (restored && dvm_join(marker, sizeof(marker), root, DVM_PENDING_PATH))
        (void)unlink(marker);
    if (restored && dvm_join(blob, sizeof(blob), root, DVM_PENDING_BYTES))
        (void)unlink(blob);
    int rebuild_rc = restored
        ? zcl_devagent_run_make(root, "test_parallel", DVM_BUILD_TIMEOUT_MS)
        : -1;

    if (!restored) {
        dvm_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                   "RESTORE_FAILED", "restore",
                   "the mutated file could NOT be put back; the checkout is "
                   "still carrying the mutation",
                   rel, "z23 dev agent mutate --restore=true");
        return;
    }

    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.agent_mutation_check.v1");
    (void)json_push_kv_str(&reply->data, "action", "check");
    (void)json_push_kv_str(&reply->data, "checkout_root", root);
    (void)json_push_kv_str(&reply->data, "file", rel);
    (void)json_push_kv_int(&reply->data, "line", line_no);
    (void)json_push_kv_str(&reply->data, "selector", selector);
    (void)json_push_kv_str(&reply->data, "rule", mutation.rule);
    (void)json_push_kv_str(&reply->data, "changed_from", mutation.before);
    (void)json_push_kv_str(&reply->data, "changed_to", mutation.after);
    (void)json_push_kv_int(&reply->data, "column", (int64_t)mutation.column);
    (void)json_push_kv_str(&reply->data, "line_before", line);
    (void)json_push_kv_str(&reply->data, "line_after", mutated);
    dvm_push_stage(&reply->data, "baseline", &before);
    dvm_push_stage(&reply->data, "mutated", &after);
    (void)json_push_kv_bool(&reply->data, "noticed", noticed);
    (void)json_push_kv_str(&reply->data, "noticed_by", noticed_by);
    (void)json_push_kv_bool(&reply->data, "restored", true);
    (void)json_push_kv_int(&reply->data, "rebuild_exit_code", rebuild_rc);
    (void)json_push_kv_str(
        &reply->data, "means",
        noticed ? "the mutation was caught: this line is covered"
                : "the group passed with the line BROKEN — its coverage of "
                  "this line proves nothing");
    (void)json_push_kv_str(
        &reply->data, "next_action",
        noticed ? "./tools/agent_fast_ci.sh verify-change"
                : "add an assertion that fails when this line changes, then "
                  "rerun this exact command");
}
