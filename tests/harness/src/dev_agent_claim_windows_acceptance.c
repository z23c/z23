/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Native Windows claim acceptance against isolated linked Git trees. */

#if defined(_WIN32)
#include "../../../tools/command/native_command.h"
#include "json/json.h"
#include "platform/private_directory.h"
#include "platform/process_lifecycle.h"
#include "util/file_io.h"
#include <windows.h>
#include <limits.h>
#include <wchar.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Link the real handler and persistence; only the command reply envelope is
 * supplied here, so this qualifies the handler rather than the dispatcher. */
void zcl_native_handle_dev_agent_claim(const struct zcl_command_request *,
                                       struct zcl_command_reply *);
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

static bool wc_format_root(char *out, size_t cap)
{
    char cwd[1024];
    if (!getcwd(cwd, sizeof(cwd))) return false;
    int n = snprintf(out, cap, "%s/test-tmp/claim_windows_%lu_fixture", cwd,
                     (unsigned long)GetCurrentProcessId());
    return n > 0 && (size_t)n < cap;
}
#define WC_CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "claim Windows fixture: %s:%d: %s\n", __FILE__, __LINE__, #x); \
    goto cleanup; } } while (0)

static bool wc_wide(const char *path, wchar_t *out, size_t cap)
{
    return cap <= INT_MAX && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        path, -1, out, (int)cap) > 0;
}

static bool wc_mkdir(const char *path)
{
    wchar_t wide[2048];
    return wc_wide(path, wide, 2048) && CreateDirectoryW(wide, NULL);
}

static bool wc_remove_file(const wchar_t *path, DWORD attrs)
{
    if (attrs & FILE_ATTRIBUTE_READONLY) {
        DWORD writable = attrs & ~FILE_ATTRIBUTE_READONLY;
        if (!SetFileAttributesW(path, writable ? writable : FILE_ATTRIBUTE_NORMAL)) return false;
    }
    return DeleteFileW(path) != 0;
}
static bool wc_remove_wide(const wchar_t *path, unsigned depth);

static bool wc_remove_entries(const wchar_t *path, const wchar_t *pattern,
                              unsigned depth)
{
    wchar_t child[2048];
    int n;
    WIN32_FIND_DATAW entry;
    HANDLE find = FindFirstFileW(pattern, &entry);
    if (find == INVALID_HANDLE_VALUE) return false;
    bool ok = true;
    do {
        if (wcscmp(entry.cFileName, L".") == 0 || wcscmp(entry.cFileName, L"..") == 0) continue;
        n = swprintf(child, 2048, L"%ls\\%ls", path, entry.cFileName);
        if (n < 0 || n >= 2048 ||
            !wc_remove_wide(child, depth + 1)) { ok = false; break; }
    } while (FindNextFileW(find, &entry));
    if (ok && GetLastError() != ERROR_NO_MORE_FILES) ok = false;
    if (!FindClose(find)) ok = false;
    return ok;
}

/* This removes only the newly created private root; refuse links and bound depth. */
static bool wc_remove_wide(const wchar_t *path, unsigned depth)
{
    if (depth > 32) return false;
    DWORD attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) return wc_remove_file(path, attrs);
    wchar_t pattern[2048];
    int n = swprintf(pattern, 2048, L"%ls\\*", path);
    if (n < 0 || n >= 2048) return false;
    return wc_remove_entries(path, pattern, depth) && RemoveDirectoryW(path) != 0;
}

/* Resolve a real directory through an opened final component, never a final
 * reparse point. The fixture is private and must not be modified concurrently. */
static bool wc_final_directory(const wchar_t *path, wchar_t out[2048])
{
    HANDLE h = CreateFileW(path, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    FILE_ATTRIBUTE_TAG_INFO info;
    bool ok = GetFileInformationByHandleEx(h, FileAttributeTagInfo,
        &info, sizeof(info)) && (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        !(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
    DWORD n = ok ? GetFinalPathNameByHandleW(h, out, 2048, FILE_NAME_NORMALIZED) : 0;
    if (!CloseHandle(h)) ok = false;
    return ok && n > 0 && n < 2048;
}

static bool wc_direct_child(const wchar_t *wide, const wchar_t *parent_final,
                            const wchar_t *root_final)
{
    const wchar_t *leaf = wcsrchr(wide, L'/');
    const wchar_t *backslash = wcsrchr(wide, L'\\');
    if (!leaf || (backslash && backslash > leaf)) leaf = backslash;
    if (!leaf || !leaf[1]) return false;
    size_t plen = wcslen(parent_final);
    size_t rlen = wcslen(root_final);
    if (plen >= rlen || root_final[plen] != L'\\' ||
        CompareStringOrdinal(parent_final, (int)plen, root_final, (int)plen, TRUE) != CSTR_EQUAL ||
        CompareStringOrdinal(root_final + plen + 1, -1, leaf + 1, -1, TRUE) != CSTR_EQUAL)
        return false;
    return true;
}

static bool wc_remove_fixture(const char *root)
{
    char expected[1024], parent[1024];
    wchar_t wide[2048], parent_wide[2048], root_final[2048], parent_final[2048];
    if (!wc_format_root(expected, sizeof(expected)) || strcmp(root, expected) != 0 ||
        !getcwd(parent, sizeof(parent))) return false;
    size_t n = strlen(parent);
    if (n + sizeof("/test-tmp") > sizeof(parent)) return false;
    memcpy(parent + n, "/test-tmp", sizeof("/test-tmp"));
    if (!wc_wide(root, wide, 2048) || !wc_wide(parent, parent_wide, 2048) ||
        !wc_final_directory(wide, root_final) ||
        !wc_final_directory(parent_wide, parent_final)) return false;
    if (!wc_direct_child(wide, parent_final, root_final)) return false;
    return wc_remove_wide(wide, 0);
}

static bool wc_write(const char *path, const char *text)
{
    wchar_t wide[2048];
    if (!wc_wide(path, wide, 2048)) return false;
    FILE *f = _wfopen(wide, L"wb");
    if (!f) return false;
    size_t len = strlen(text);
    bool ok = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

/* The fixture runs only the explicitly configured trusted Git image, never a
 * shell or an image selected by the repository under test. */
static bool wc_git(const char *image, const char *home,
                   const char *const argv[])
{
    char root_env[2048], path_env[8192], home_env[2048], config_env[2048], output[8192];
    const char *root = getenv("SystemRoot"), *path = getenv("PATH");
    if (!root || !path || snprintf(root_env, sizeof(root_env), "SystemRoot=%s", root) >= (int)sizeof(root_env) ||
        snprintf(path_env, sizeof(path_env), "Path=%s", path) >= (int)sizeof(path_env) ||
        snprintf(home_env, sizeof(home_env), "HOME=%s", home) >= (int)sizeof(home_env) ||
        snprintf(config_env, sizeof(config_env), "GIT_CONFIG_GLOBAL=%s/no-gitconfig", home) >= (int)sizeof(config_env)) return false;
    const char *env[] = {root_env, path_env, home_env, "GIT_CONFIG_NOSYSTEM=1",
        config_env, "GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat", NULL};
    const struct platform_process_options options = {
        .image = image, .argv = argv, .env = env,
    };
    struct platform_process_capture_result result = {0};
    bool ran = platform_process_capture_stdout(&options, output, sizeof(output),
                                                30000u, &result);
    if (!ran || result.timed_out || result.output_truncated || result.exit_code != 0) {
        fprintf(stderr, "claim fixture Git failed: %s launched=%d exit=%lu timeout=%d truncated=%d\n",
                argv[1], ran, (unsigned long)result.exit_code,
                result.timed_out, result.output_truncated);
        return false;
    }
    return true;
}

static bool wc_check_reply(const struct zcl_command_reply *reply,
                           bool valid, const char *file,
                           const char *expected_code, int expected_live)
{
    bool passed = reply->status == ZCL_COMMAND_STATUS_PASSED;
    bool ok = valid && (expected_code ? (!passed && strcmp(reply->error.code, expected_code) == 0) : passed);
    if (ok && expected_live >= 0) {
        const struct json_value *live = json_get(&reply->data, "live");
        ok = live && live->type == JSON_INT && json_get_int(live) == expected_live;
    }
    if (!ok) fprintf(stderr, "claim fixture call: %s expected=%s got=%s message=%s\n",
                     file ? file : "release", expected_code ? expected_code : "passed", reply->error.code, reply->error.message);
    return ok;
}

static bool wc_call(const char *cwd, const char *file, bool release,
                    const char *expected_code, int expected_live)
{
    struct json_value input, files, item;
    struct zcl_command_request request = {0};
    struct zcl_command_reply reply;
    json_init(&input); json_set_object(&input);
    json_init(&files); json_set_array(&files);
    json_init(&item);
    bool made = json_push_kv_str(&input, "cwd", cwd);
    if (release) made = made && json_push_kv_bool(&input, "release", true);
    else {
        json_set_str(&item, file);
        made = made && json_push_back(&files, &item) &&
            json_push_kv_str(&input, "story", "fixture-story") &&
            json_push_kv(&input, "files", &files);
    }
    request.input = &input;
    memset(&reply, 0, sizeof(reply));
    json_init(&reply.data); json_set_object(&reply.data);
    bool valid = made;
    if (valid) zcl_native_handle_dev_agent_claim(&request, &reply);
    bool ok = wc_check_reply(&reply, valid, file, expected_code, expected_live);
    json_free(&reply.data);
    json_free(&item); json_free(&files); json_free(&input);
    return ok;
}

/* Read the observed ledger with UTF-16, independently of the handler's
 * production reader, so an ANSI code page cannot mask lost bytes. */
static bool wc_read(const char *path, char **out, size_t *len)
{
    wchar_t wide[2048];
    *out = NULL; *len = 0;
    if (!wc_wide(path, wide, 2048)) return false;
    FILE *f = _wfopen(wide, L"rb");
    if (!f) return false;
    char *bytes = malloc(32769);
    if (!bytes) { fclose(f); return false; }
    size_t n = fread(bytes, 1, 32769, f);
    bool ok = !ferror(f) && n < 32769;
    if (fclose(f) != 0) ok = false;
    if (!ok) { free(bytes); return false; }
    bytes[n] = 0; *out = bytes; *len = n;
    return true;
}

static bool wc_cases(const char *repo, const char *nested,
                     const char *other, const char *ledger)
{
    bool ok = false;
    char *before = NULL, *after = NULL;
    size_t before_len = 0, after_len = 0;
    WC_CHECK(wc_call(repo, "engine/a.c", false, NULL, 1));
    WC_CHECK(wc_call(repo, "engine/a.c", false, NULL, 1));
    WC_CHECK(wc_call(nested, "engine/a.c", false, NULL, 1));
    WC_CHECK(wc_read(ledger, &before, &before_len));
    WC_CHECK(wc_call(other, "ENGINE\\A.C", false, "CLAIM_OVERLAP", -1));
    WC_CHECK(wc_read(ledger, &after, &after_len));
    WC_CHECK(before_len == after_len && memcmp(before, after, before_len) == 0);
    free(after); after = NULL;
    WC_CHECK(wc_call(other, "engine/b.c", false, NULL, 2));
    WC_CHECK(wc_read(ledger, &after, &after_len));
    WC_CHECK(strstr(after, "engine/a.c") && strstr(after, "engine/b.c"));
    free(after); after = NULL;
    WC_CHECK(wc_call(repo, "engine/\xc3\xa9.c", false, NULL, 2));
    free(before); before = NULL;
    WC_CHECK(wc_read(ledger, &before, &before_len));
    WC_CHECK(wc_call(other, "ENGINE/\xc3\x89.c", false, "CLAIM_OVERLAP", -1));
    WC_CHECK(wc_read(ledger, &after, &after_len));
    WC_CHECK(before_len == after_len && memcmp(before, after, before_len) == 0);
    free(after); after = NULL;
    WC_CHECK(wc_call(repo, NULL, true, NULL, 1));
    WC_CHECK(wc_call(other, "engine/a.c", false, NULL, 1));
    WC_CHECK(wc_call(repo, "engine/COM\xc2\xb9.txt", false, "CLAIM_PATH_REFUSED", -1));
    WC_CHECK(wc_call(repo, "engine/COM\xc2\xb2.txt", false, "CLAIM_PATH_REFUSED", -1));
    WC_CHECK(wc_call(repo, "engine/COM\xc2\xb3.txt", false, "CLAIM_PATH_REFUSED", -1));
    WC_CHECK(wc_call(repo, "engine/LPT\xc2\xb9.txt", false, "CLAIM_PATH_REFUSED", -1));
    WC_CHECK(wc_call(repo, "engine/LPT\xc2\xb2.txt", false, "CLAIM_PATH_REFUSED", -1));
    WC_CHECK(wc_call(repo, "engine/LPT\xc2\xb3.txt", false, "CLAIM_PATH_REFUSED", -1));
    WC_CHECK(wc_call(repo, "engine/NUL.txt", false, "CLAIM_PATH_REFUSED", -1));
    WC_CHECK(wc_call(repo, "engine/name.", false, "CLAIM_PATH_REFUSED", -1));
    WC_CHECK(wc_call(repo, "engine/a.c:stream", false, "CLAIM_PATH_REFUSED", -1));
    WC_CHECK(wc_call(repo, "C:\\escape.c", false, "CLAIM_PATH_REFUSED", -1));
    WC_CHECK(wc_call(repo, "\\\\server\\share\\escape.c", false, "CLAIM_PATH_REFUSED", -1));
    free(before); before = NULL;
    WC_CHECK(wc_read(ledger, &before, &before_len));
    WC_CHECK(_putenv_s("ZCL_DEV_GIT_EXE", "relative-git.exe") == 0);
    WC_CHECK(wc_call(repo, "engine/c.c", false, "GIT_FAILED", -1));
    WC_CHECK(wc_read(ledger, &after, &after_len));
    WC_CHECK(before_len == after_len && memcmp(before, after, before_len) == 0);
    ok = true;
cleanup:
    free(before); free(after);
    return ok;
}
static bool wc_fixture(void)
{
    bool ok = false, root_created = false;
    char root[1024] = {0}, repo[1200], other[1200], nested[1400], file[1400], ledger[1400];
    const char *configured = getenv("ZCL_DEV_GIT_EXE");
    char *saved = configured ? strdup(configured) : NULL;
    WC_CHECK(configured && saved && configured[0] && configured[1] == ':' &&
             (configured[2] == '/' || configured[2] == '\\'));
    char parent[1024];
    WC_CHECK(getcwd(parent, sizeof(parent)) != NULL);
    size_t parent_len = strlen(parent);
    WC_CHECK(parent_len + sizeof("/test-tmp") <= sizeof(parent));
    memcpy(parent + parent_len, "/test-tmp", sizeof("/test-tmp"));
    WC_CHECK(platform_private_directory_ensure(parent));
    WC_CHECK(wc_format_root(root, sizeof(root)));
    WC_CHECK(platform_private_directory_create(root));
    root_created = true;
    WC_CHECK(snprintf(repo, sizeof(repo), "%s/repo space \xe4\xb8\xad", root) < (int)sizeof(repo));
    WC_CHECK(snprintf(other, sizeof(other), "%s/other space \xe4\xb8\xad", root) < (int)sizeof(other));
    WC_CHECK(snprintf(nested, sizeof(nested), "%s/nested directory", repo) < (int)sizeof(nested));
    WC_CHECK(snprintf(file, sizeof(file), "%s/a.c", repo) < (int)sizeof(file));
    WC_CHECK(snprintf(ledger, sizeof(ledger), "%s/.git/z23-agent-claims.jsonl", repo) < (int)sizeof(ledger));
    WC_CHECK(wc_mkdir(repo));
    WC_CHECK(wc_mkdir(nested));
    const char *init[] = {saved, "-C", repo, "-c", "init.defaultBranch=main", "init", "-q", NULL};
    const char *add[] = {saved, "-C", repo, "add", "--", "a.c", NULL};
    const char *commit[] = {saved, "-C", repo, "-c", "user.name=Z23 Test", "-c", "user.email=z23-test@example.invalid", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base", NULL};
    const char *worktree[] = {saved, "-C", repo, "worktree", "add", "-q", "-b", "other", other, NULL};
    WC_CHECK(wc_git(saved, root, init) && wc_write(file, "int a;\n") &&
             wc_git(saved, root, add) && wc_git(saved, root, commit) && wc_git(saved, root, worktree));
    WC_CHECK(wc_cases(repo, nested, other, ledger));
    ok = true;
cleanup:
    if (saved && _putenv_s("ZCL_DEV_GIT_EXE", saved) != 0) ok = false;
    free(saved);
    if (root_created && !wc_remove_fixture(root)) {
        fprintf(stderr, "claim Windows fixture cleanup failed: %s\n", root);
        ok = false;
    }
    return ok;
}
int main(void)
{
    if (!wc_fixture()) {
        fprintf(stderr, "dev_agent_claim_windows_acceptance: FAIL\n");
        return 1;
    }
    printf("dev_agent_claim_windows_acceptance: PASS (real handler, not dispatcher)\n");
    return 0;
}
#else
typedef int dev_agent_claim_windows_acceptance_not_built;
#endif
