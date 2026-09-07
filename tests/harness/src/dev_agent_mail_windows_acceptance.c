/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Exercise the real native mail handler on an isolated Windows store. */
#if defined(_WIN32)
#include "../../../tools/command/native_command.h"
#include "../../../tools/command/native_devagent.h"
#include "json/json.h"
#include "platform/directory_transaction.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/state_root.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

void zcl_native_handle_dev_agent_mail(const struct zcl_command_request *,
                                    struct zcl_command_reply *);

/* This filesystem fixture needs no checkout navigation or network. */
bool zcl_devagent_checkout_root(const char *start, char *out, size_t cap)
{
    (void)start;
    if (out && cap) out[0] = 0;
    return false;
}

/* Record the handler's refusal envelope without linking the unrelated
 * command dispatcher and its agent-spending policy. Filesystem operations
 * and JSON parsing/serialization below use their production implementations. */
void zcl_command_reply_fail(struct zcl_command_reply *reply,
                           enum zcl_command_status status,
                           enum zcl_command_exit exit_code,
                           const char *code, const char *phase,
                           bool retryable, bool mutated,
                           const char *message, const char *evidence)
{
    (void)phase; (void)retryable; (void)mutated; (void)evidence;
    reply->status = status;
    reply->exit_code = exit_code;
    (void)snprintf(reply->error.code, sizeof(reply->error.code), "%s", code);
    (void)snprintf(reply->error.message, sizeof(reply->error.message), "%s", message);
}

static int fail(const char *message)
{
    fprintf(stderr, "dev_agent_mail_windows_acceptance: FAIL: %s\n", message);
    return 1;
}

static bool call(const char *text, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    if (!json_read(&input, text, strlen(text))) return false;
    struct zcl_command_request request = {.input = &input};
    memset(reply, 0, sizeof(*reply));
    json_init(&reply->data);
    json_set_object(&reply->data);
    zcl_native_handle_dev_agent_mail(&request, reply);
    json_free(&input);
    return true;
}

static bool succeeds(const char *text)
{
    struct zcl_command_reply reply;
    if (!call(text, &reply)) return false;
    bool ok = reply.exit_code == 0;
    if (!ok) fprintf(stderr, "mail refusal: %s: %s\n",
                     reply.error.code, reply.error.message);
    json_free(&reply.data);
    return ok;
}

static bool private_regular(struct platform_private_file *file)
{
    struct platform_directory_child view = {.native = file->native};
    struct platform_directory_child_info info;
    return platform_directory_child_info(&view, &info) &&
           info.current_user_only && info.link_count == 1;
}

/* Fixture state threaded through the case functions below. main() stays a
 * flat sequence of case calls so its own complexity does not recreate the
 * one giant function this file used to be. */
struct dvx_fixture {
    char root[4096];
    char state[4096];
    char mail[4160];
    char outbox[4200];
    char cursor[4200];
    const char *post;
};

static const char *dvx_setup_state_root(struct dvx_fixture *fx)
{
    wchar_t temp[MAX_PATH], locator[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, temp);
    if (!n || n >= MAX_PATH || !GetTempFileNameW(temp, L"zma", 0, locator) ||
        !DeleteFileW(locator) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, locator, -1,
                             fx->root, sizeof(fx->root), NULL, NULL) ||
        !platform_private_directory_create(fx->root) ||
        !SetEnvironmentVariableW(L"ZCL_STATE_ROOT", locator) ||
        !platform_state_root(fx->state, sizeof(fx->state)))
        return "isolated private state root";
    return NULL;
}

static const char *dvx_build_paths(struct dvx_fixture *fx)
{
    if (snprintf(fx->mail, sizeof(fx->mail), "%s/mail", fx->state) >=
            (int)sizeof(fx->mail) ||
        snprintf(fx->outbox, sizeof(fx->outbox), "%s/outbox.jsonl",
                 fx->mail) >= (int)sizeof(fx->outbox) ||
        snprintf(fx->cursor, sizeof(fx->cursor), "%s/cursor.windows",
                 fx->mail) >= (int)sizeof(fx->cursor))
        return "fixture paths";
    return NULL;
}

static const char *dvx_post_pull_round_trip(struct dvx_fixture *fx)
{
    if (!succeeds(fx->post) || !succeeds(fx->post) ||
        !platform_private_directory_ensure(fx->mail))
        return "post and private directory";

    struct zcl_command_reply reply;
    if (!call("{\"action\":\"pull\",\"since\":0}", &reply))
        return "pull input";
    bool pulled = reply.exit_code == 0 &&
        json_get_int(json_get(&reply.data, "count")) == 2 &&
        json_get_int(json_get(&reply.data, "cursor")) == 2;
    json_free(&reply.data);
    return pulled ? NULL : "post/pull sequence round trip";
}

/* Opens the outbox locked and leaves it open (the caller's busy-refuse
 * check needs the same held lock), returning the size it observed. */
static const char *dvx_outbox_private_and_content(
    struct dvx_fixture *fx, struct platform_private_file *file,
    uint64_t *out_size)
{
    char bytes[4096];
    uint64_t size = 0;
    if (!platform_private_file_open_locked(fx->outbox, file) ||
        !private_regular(file) ||
        !platform_private_file_size(file, &size) || size >= sizeof(bytes) ||
        !platform_private_file_read_at(file, bytes, (size_t)size, 0))
        return "outbox is a private regular file";
    bytes[size] = 0;
    if (strchr(bytes, '\r') || !strchr(bytes, '\n'))
        return "outbox preserves canonical LF bytes";
    *out_size = size;
    return NULL;
}

static const char *dvx_busy_outbox_refuses(
    struct dvx_fixture *fx, struct platform_private_file *file,
    uint64_t size)
{
    struct zcl_command_reply reply;
    uint64_t after = 0;
    if (!call(fx->post, &reply)) return "contended post input";
    bool refused = reply.exit_code != 0 &&
        strcmp(reply.error.code, "MAIL_WRITE_FAILED") == 0;
    json_free(&reply.data);
    if (!refused || !platform_private_file_size(file, &after) || after != size)
        return "busy outbox refuses without changing bytes";
    platform_private_file_close(file);
    return NULL;
}

static const char *dvx_hardlink_outbox_refuses(
    struct dvx_fixture *fx, struct platform_private_file *file,
    uint64_t size)
{
    char alias[4200];
    wchar_t outbox_wide[4200], alias_wide[4200];
    if (snprintf(alias, sizeof(alias), "%s/alias.jsonl", fx->mail) >=
            (int)sizeof(alias) ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, fx->outbox, -1,
                             outbox_wide, 4200) ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, alias, -1,
                             alias_wide, 4200) ||
        !CreateHardLinkW(alias_wide, outbox_wide, NULL))
        return "hard-linked outbox fixture";
    struct zcl_command_reply reply;
    if (!call(fx->post, &reply)) return "hard-linked post input";
    bool refused = reply.exit_code != 0 &&
        strcmp(reply.error.code, "MAIL_WRITE_FAILED") == 0;
    json_free(&reply.data);
    uint64_t after = 0;
    if (!refused || !DeleteFileW(alias_wide) ||
        !platform_private_file_open_locked(fx->outbox, file) ||
        !platform_private_file_size(file, &after) || after != size)
        return "hard-linked outbox refuses without changing bytes";
    platform_private_file_close(file);
    return NULL;
}

static const char *dvx_ack_cursor_replacement(
    struct dvx_fixture *fx, struct platform_private_file *file)
{
    char bytes[4096];
    uint64_t size = 0;
    if (!succeeds("{\"action\":\"ack\",\"agent\":\"windows\",\"cursor\":1}") ||
        !succeeds("{\"action\":\"ack\",\"agent\":\"windows\",\"cursor\":2}") ||
        !platform_private_file_open_locked(fx->cursor, file) ||
        !private_regular(file) ||
        !platform_private_file_size(file, &size) || size != 2 ||
        !platform_private_file_read_at(file, bytes, 2, 0) ||
        memcmp(bytes, "2\n", 2) != 0)
        return "private cursor replacement";
    platform_private_file_close(file);
    return NULL;
}

static const char *dvx_blocked_cursor_directory(struct dvx_fixture *fx)
{
    char blocked[4200];
    if (snprintf(blocked, sizeof(blocked), "%s/cursor.blocked", fx->mail) >=
            (int)sizeof(blocked) ||
        !platform_private_directory_create(blocked))
        return "blocked cursor fixture";
    struct zcl_command_reply reply;
    if (!call("{\"action\":\"ack\",\"agent\":\"blocked\",\"cursor\":3}",
              &reply))
        return "blocked cursor fixture";
    bool refused = reply.exit_code != 0 &&
        strcmp(reply.error.code, "MAIL_WRITE_FAILED") == 0;
    json_free(&reply.data);
    if (!refused || !platform_private_directory_remove_empty(blocked))
        return "cursor replacement preserves a directory destination";
    return NULL;
}

static const char *dvx_final_post_and_cleanup(struct dvx_fixture *fx)
{
    if (!succeeds(fx->post)) return "post succeeds after releasing lock";
    if (!platform_private_file_unlink_missing_ok(fx->outbox) ||
        !platform_private_file_unlink_missing_ok(fx->cursor) ||
        !platform_private_directory_remove_empty(fx->mail) ||
        !platform_private_directory_remove_empty(fx->state))
        return "fixture cleanup";
    if (snprintf(fx->state, sizeof(fx->state), "%s/z23", fx->root) >=
            (int)sizeof(fx->state) ||
        !platform_private_directory_remove_empty(fx->state) ||
        !platform_private_directory_remove_empty(fx->root))
        return "fixture root cleanup";
    return NULL;
}

int main(void)
{
    struct dvx_fixture fx = {0};
    fx.post = "{\"action\":\"post\",\"from\":\"windows\",\"to\":\"peer\","
              "\"kind\":\"note\",\"body\":\"first\"}";
    struct platform_private_file file;
    platform_private_file_init(&file);
    uint64_t outbox_size = 0;
    const char *err;
    if ((err = dvx_setup_state_root(&fx))) return fail(err);
    if ((err = dvx_build_paths(&fx))) return fail(err);
    if ((err = dvx_post_pull_round_trip(&fx))) return fail(err);
    if ((err = dvx_outbox_private_and_content(&fx, &file, &outbox_size)))
        return fail(err);
    if ((err = dvx_busy_outbox_refuses(&fx, &file, outbox_size)))
        return fail(err);
    if ((err = dvx_hardlink_outbox_refuses(&fx, &file, outbox_size)))
        return fail(err);
    if ((err = dvx_ack_cursor_replacement(&fx, &file))) return fail(err);
    if ((err = dvx_blocked_cursor_directory(&fx))) return fail(err);
    if ((err = dvx_final_post_and_cleanup(&fx))) return fail(err);
    puts("dev_agent_mail_windows_acceptance: PASS");
    return 0;
}
#else
typedef int dev_agent_mail_windows_acceptance_not_built;
#endif
