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

int main(void)
{
    wchar_t temp[MAX_PATH], locator[MAX_PATH];
    char root[4096], state[4096], mail[4160], outbox[4200], cursor[4200];
    DWORD n = GetTempPathW(MAX_PATH, temp);
    if (!n || n >= MAX_PATH || !GetTempFileNameW(temp, L"zma", 0, locator) ||
        !DeleteFileW(locator) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, locator, -1,
                             root, sizeof(root), NULL, NULL) ||
        !platform_private_directory_create(root) ||
        !SetEnvironmentVariableW(L"ZCL_STATE_ROOT", locator) ||
        !platform_state_root(state, sizeof(state)))
        return fail("isolated private state root");
    if (snprintf(mail, sizeof(mail), "%s/mail", state) >= (int)sizeof(mail) ||
        snprintf(outbox, sizeof(outbox), "%s/outbox.jsonl", mail) >= (int)sizeof(outbox) ||
        snprintf(cursor, sizeof(cursor), "%s/cursor.windows", mail) >= (int)sizeof(cursor))
        return fail("fixture paths");

    const char *post = "{\"action\":\"post\",\"from\":\"windows\",\"to\":\"peer\","
                       "\"kind\":\"note\",\"body\":\"first\"}";
    if (!succeeds(post) || !succeeds(post) ||
        !platform_private_directory_ensure(mail))
        return fail("post and private directory");

    struct zcl_command_reply reply;
    if (!call("{\"action\":\"pull\",\"since\":0}", &reply))
        return fail("pull input");
    bool pulled = reply.exit_code == 0 &&
        json_get_int(json_get(&reply.data, "count")) == 2 &&
        json_get_int(json_get(&reply.data, "cursor")) == 2;
    json_free(&reply.data);
    if (!pulled) return fail("post/pull sequence round trip");

    struct platform_private_file file;
    platform_private_file_init(&file);
    uint64_t size = 0, after = 0;
    char bytes[4096];
    if (!platform_private_file_open_locked(outbox, &file) ||
        !private_regular(&file) ||
        !platform_private_file_size(&file, &size) || size >= sizeof(bytes) ||
        !platform_private_file_read_at(&file, bytes, (size_t)size, 0))
        return fail("outbox is a private regular file");
    bytes[size] = 0;
    if (strchr(bytes, '\r') || !strchr(bytes, '\n'))
        return fail("outbox preserves canonical LF bytes");
    if (!call(post, &reply)) return fail("contended post input");
    bool refused = reply.exit_code != 0 &&
        strcmp(reply.error.code, "MAIL_WRITE_FAILED") == 0;
    json_free(&reply.data);
    if (!refused || !platform_private_file_size(&file, &after) || after != size)
        return fail("busy outbox refuses without changing bytes");
    platform_private_file_close(&file);

    char alias[4200];
    wchar_t outbox_wide[4200], alias_wide[4200];
    if (snprintf(alias, sizeof(alias), "%s/alias.jsonl", mail) >= (int)sizeof(alias) ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, outbox, -1,
                             outbox_wide, 4200) ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, alias, -1,
                             alias_wide, 4200) ||
        !CreateHardLinkW(alias_wide, outbox_wide, NULL))
        return fail("hard-linked outbox fixture");
    if (!call(post, &reply)) return fail("hard-linked post input");
    refused = reply.exit_code != 0 &&
        strcmp(reply.error.code, "MAIL_WRITE_FAILED") == 0;
    json_free(&reply.data);
    if (!refused || !DeleteFileW(alias_wide) ||
        !platform_private_file_open_locked(outbox, &file) ||
        !platform_private_file_size(&file, &after) || after != size)
        return fail("hard-linked outbox refuses without changing bytes");
    platform_private_file_close(&file);

    if (!succeeds("{\"action\":\"ack\",\"agent\":\"windows\",\"cursor\":1}") ||
        !succeeds("{\"action\":\"ack\",\"agent\":\"windows\",\"cursor\":2}") ||
        !platform_private_file_open_locked(cursor, &file) ||
        !private_regular(&file) ||
        !platform_private_file_size(&file, &size) || size != 2 ||
        !platform_private_file_read_at(&file, bytes, 2, 0) ||
        memcmp(bytes, "2\n", 2) != 0)
        return fail("private cursor replacement");
    platform_private_file_close(&file);

    char blocked[4200];
    if (snprintf(blocked, sizeof(blocked), "%s/cursor.blocked", mail) >= (int)sizeof(blocked) ||
        !platform_private_directory_create(blocked) ||
        !call("{\"action\":\"ack\",\"agent\":\"blocked\",\"cursor\":3}", &reply))
        return fail("blocked cursor fixture");
    refused = reply.exit_code != 0 &&
        strcmp(reply.error.code, "MAIL_WRITE_FAILED") == 0;
    json_free(&reply.data);
    if (!refused || !platform_private_directory_remove_empty(blocked))
        return fail("cursor replacement preserves a directory destination");

    if (!succeeds(post)) return fail("post succeeds after releasing lock");
    if (!platform_private_file_unlink_missing_ok(outbox) ||
        !platform_private_file_unlink_missing_ok(cursor) ||
        !platform_private_directory_remove_empty(mail) ||
        !platform_private_directory_remove_empty(state))
        return fail("fixture cleanup");
    if (snprintf(state, sizeof(state), "%s/z23", root) >= (int)sizeof(state) ||
        !platform_private_directory_remove_empty(state) ||
        !platform_private_directory_remove_empty(root))
        return fail("fixture root cleanup");
    puts("dev_agent_mail_windows_acceptance: PASS");
    return 0;
}
#else
typedef int dev_agent_mail_windows_acceptance_not_built;
#endif
