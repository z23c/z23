/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.lane.new (tools/command/native_dev_lane.c).
 *
 * THE PROPERTY THIS GROUP EXISTS FOR: an agent worktree gets the proof's
 * vendored dependencies as independent inodes (st_nlink == 1, st_ino
 * differs from ROOT). A hardlink would bump the shared inode's ctime and
 * refuse every in-flight proof whose seal covered that file.
 *
 * The handler is called DIRECTLY after registry input validation, the same
 * way the CLI does. ROOT is the process cwd's git checkout, so each case
 * chdirs into a fixture repo for the call and restores cwd afterwards.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DLN_PATH "dev.lane.new"

static bool dln_git(const char *dir, const char *const *args)
{
    const char *argv[32];
    size_t n = 0;
    char out[8192];
    argv[n++] = "git";
    if (dir && dir[0]) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return false;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    return zcl_spawn_capture(argv, out, sizeof(out), 30000) == 0;
}

static bool dln_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t len;
    bool wrote;
    if (!f)
        return false;
    len = strlen(text);
    wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

static bool dln_mkdir_p(const char *path)
{
    char buf[1400];
    size_t len = path ? strlen(path) : 0;
    char *p;
    if (!len || len >= sizeof(buf))
        return false;
    memcpy(buf, path, len + 1);
    for (p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(buf, 0700) != 0 && errno != EEXIST)
                return false;
            *p = '/';
        }
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

static bool dln_write_dep(const char *root, const char *rel, const char *body)
{
    char path[1400], dir[1400], *slash;
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", root, rel) >=
        sizeof(path))
        return false;
    (void)snprintf(dir, sizeof(dir), "%s", path);
    slash = strrchr(dir, '/');
    if (slash)
        *slash = '\0';
    return dln_mkdir_p(dir) && dln_write(path, body);
}

static bool dln_commit(const char *dir, const char *message)
{
    const char *add[] = { "add", "-A", NULL };
    const char *commit[] = { "-c", "user.name=Z23 Test",
                             "-c", "user.email=z23-test@example.invalid",
                             "-c", "commit.gpgsign=false",
                             "commit", "-q", "-m", message, NULL };
    return dln_git(dir, add) && dln_git(dir, commit);
}

static bool dln_plant_deps(const char *root)
{
    return dln_write_dep(root, "vendor/lib/libfoo.a", "fake\n") &&
           dln_write_dep(root, "vendor/include/foo.h", "fake\n") &&
           dln_write_dep(root, "vendor/tor/libtor.a", "fake\n") &&
           dln_write_dep(root,
                         "vendor/tor/src/ext/ed25519/donna/"
                         "libed25519_donna.a",
                         "fake\n") &&
           dln_write_dep(root,
                         "vendor/tor/src/ext/ed25519/ref10/"
                         "libed25519_ref10.a",
                         "fake\n") &&
           dln_write_dep(root,
                         "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
                         "fake\n") &&
           dln_write_dep(root, "build/githooks/pre-push", "#!/bin/sh\n") &&
           dln_write_dep(root, "build/hotswap/zcl_rollback_fixture_a.so",
                         "fake\n") &&
           dln_write_dep(root, "build/hotswap/zcl_rollback_fixture_b.so",
                         "fake\n");
}

static const char *const dln_check_rels[] = {
    "vendor/lib/libfoo.a",
    "vendor/include/foo.h",
    "vendor/tor/libtor.a",
    "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
    "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
    "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
    "build/githooks/pre-push",
    "build/hotswap/zcl_rollback_fixture_a.so",
    "build/hotswap/zcl_rollback_fixture_b.so",
    NULL,
};

static bool dln_fixture(const char *root)
{
    const char *init[] = { "-c", "init.defaultBranch=main", "init", "-q",
                           root, NULL };
    if (!dln_git(NULL, init))
        return false;
    if (!dln_write_dep(root, "Makefile",
                       "install-hooks:\n\t@true\n") ||
        !dln_write_dep(root, "seed.txt", "seed\n") ||
        !dln_commit(root, "base"))
        return false;
    return dln_plant_deps(root);
}

static const char *dln_str(const struct zcl_command_reply *reply,
                           const char *key)
{
    const struct json_value *v = json_get(&reply->data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v)
                                                      : "";
}

static int64_t dln_int(const struct zcl_command_reply *reply, const char *key)
{
    const struct json_value *v = json_get(&reply->data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static bool dln_bool(const struct zcl_command_reply *reply, const char *key)
{
    const struct json_value *v = json_get(&reply->data, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static void dln_call(const char *root, struct json_value *input,
                     struct zcl_command_reply *reply)
{
    char saved[PATH_MAX];
    struct zcl_command_request request;
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), DLN_PATH, NULL);
    char why[256];
    memset(&request, 0, sizeof(request));
    request.input = input;
    request.spec = spec;
    zcl_command_reply_init(reply, "zcl.lane_new.v1");
    if (spec &&
        !zcl_command_registry_input_validate(spec, input, why, sizeof(why))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT",
                               "validate", false, false, why, "");
        return;
    }
    if (!getcwd(saved, sizeof(saved)) || chdir(root) != 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "TEST_CHDIR",
                               "fixture", false, false,
                               "could not chdir into fixture ROOT", "");
        return;
    }
    zcl_native_handle_dev_lane_new(&request, reply);
    if (chdir(saved) != 0)
        (void)chdir("/");
}

int test_dev_lane(void);
int test_dev_lane(void)
{
    int failures = 0;

    TEST("lane: the leaf is registered with path and base") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DLN_PATH,
                                      NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->input_keys &&
               strcmp(spec->input_keys, "path,base") == 0);
        PASS();
    }

#if !defined(_WIN32)
    TEST("lane new: fresh path gets independent inodes and hooks") {
        char parent[512], root[600], lane[600], check[800], srcp[800];
        struct json_value input;
        struct zcl_command_reply reply;
        struct stat src, dst;
        size_t i;

        test_make_tmpdir(parent, sizeof(parent), "dev_lane", "fresh");
        (void)snprintf(root, sizeof(root), "%s/root", parent);
        (void)snprintf(lane, sizeof(lane), "%s/lane", parent);
        ASSERT(dln_mkdir_p(root));
        ASSERT(dln_fixture(root));

        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "path", lane);
        (void)json_push_kv_str(&input, "base", "HEAD");
        dln_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(dln_bool(&reply, "ok"));
        ASSERT_STR_EQ(dln_str(&reply, "path"), lane);
        ASSERT(strlen(dln_str(&reply, "head")) == 40);
        ASSERT(dln_int(&reply, "dependencies") == 9);
        ASSERT(dln_int(&reply, "libtor_links") == 1);
        ASSERT(dln_bool(&reply, "hooks_installed"));

        for (i = 0; dln_check_rels[i]; i++) {
            ASSERT((size_t)snprintf(srcp, sizeof(srcp), "%s/%s", root,
                                    dln_check_rels[i]) < sizeof(srcp));
            ASSERT((size_t)snprintf(check, sizeof(check), "%s/%s", lane,
                                    dln_check_rels[i]) < sizeof(check));
            ASSERT(stat(srcp, &src) == 0);
            ASSERT(stat(check, &dst) == 0);
            ASSERT(src.st_ino != dst.st_ino);
            ASSERT(dst.st_nlink == 1);
        }
        (void)snprintf(check, sizeof(check), "%s/build/githooks", lane);
        ASSERT(stat(check, &dst) == 0);
        ASSERT(S_ISDIR(dst.st_mode));

        zcl_command_reply_free(&reply);
        json_free(&input);
        {
            const char *rm[] = { "worktree", "remove", "--force", lane,
                                 NULL };
            (void)dln_git(root, rm);
        }
        PASS();
    }

    TEST("lane new: second call is idempotent and leaves mtimes") {
        char parent[512], root[600], lane[600], check[800];
        struct json_value input;
        struct zcl_command_reply reply;
        struct stat before[16], after;
        size_t i;

        test_make_tmpdir(parent, sizeof(parent), "dev_lane", "again");
        (void)snprintf(root, sizeof(root), "%s/root", parent);
        (void)snprintf(lane, sizeof(lane), "%s/lane", parent);
        ASSERT(dln_mkdir_p(root));
        ASSERT(dln_fixture(root));

        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "path", lane);
        (void)json_push_kv_str(&input, "base", "HEAD");
        dln_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(dln_int(&reply, "dependencies") == 9);
        zcl_command_reply_free(&reply);

        for (i = 0; dln_check_rels[i]; i++) {
            ASSERT((size_t)snprintf(check, sizeof(check), "%s/%s", lane,
                                    dln_check_rels[i]) < sizeof(check));
            ASSERT(stat(check, &before[i]) == 0);
        }

        dln_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(dln_bool(&reply, "ok"));
        ASSERT(dln_int(&reply, "dependencies") == 0);
        ASSERT(dln_int(&reply, "libtor_links") == 1);
        for (i = 0; dln_check_rels[i]; i++) {
            ASSERT((size_t)snprintf(check, sizeof(check), "%s/%s", lane,
                                    dln_check_rels[i]) < sizeof(check));
            ASSERT(stat(check, &after) == 0);
            ASSERT(after.st_mtime == before[i].st_mtime);
            ASSERT(after.st_mtim.tv_nsec == before[i].st_mtim.tv_nsec);
        }
        zcl_command_reply_free(&reply);
        json_free(&input);
        {
            const char *rm[] = { "worktree", "remove", "--force", lane,
                                 NULL };
            (void)dln_git(root, rm);
        }
        PASS();
    }

    TEST("lane new: missing ROOT dependency refuses and copies nothing") {
        char parent[512], root[600], lane[600], missing[800], other[800];
        struct json_value input;
        struct zcl_command_reply reply;
        struct stat st, before;
        char libtor[800];

        test_make_tmpdir(parent, sizeof(parent), "dev_lane", "missing");
        (void)snprintf(root, sizeof(root), "%s/root", parent);
        (void)snprintf(lane, sizeof(lane), "%s/lane", parent);
        ASSERT(dln_mkdir_p(root));
        ASSERT(dln_fixture(root));
        (void)snprintf(libtor, sizeof(libtor), "%s/vendor/tor/libtor.a",
                       root);
        ASSERT(stat(libtor, &before) == 0);
        (void)snprintf(missing, sizeof(missing), "%s/vendor/lib", root);
        ASSERT(test_rm_rf_recursive(missing) == 0);

        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "path", lane);
        (void)json_push_kv_str(&input, "base", "HEAD");
        dln_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strstr(reply.error.code,
                      "lane.dependency_unavailable:vendor/lib") != NULL);
        ASSERT(strstr(reply.error.message,
                      "lane.dependency_unavailable:vendor/lib") != NULL);

        (void)snprintf(other, sizeof(other), "%s/vendor/tor/libtor.a",
                       lane);
        ASSERT(stat(other, &st) != 0);
        (void)snprintf(other, sizeof(other), "%s/vendor/lib", lane);
        ASSERT(stat(other, &st) != 0);
        ASSERT(stat(libtor, &st) == 0);
        ASSERT(st.st_mtime == before.st_mtime);
        ASSERT(st.st_mtim.tv_nsec == before.st_mtim.tv_nsec);

        zcl_command_reply_free(&reply);
        json_free(&input);
        {
            const char *rm[] = { "worktree", "remove", "--force", lane,
                                 NULL };
            (void)dln_git(root, rm);
        }
        PASS();
    }

    TEST("lane new: unresolvable base refuses") {
        char parent[512], root[600], lane[600];
        struct json_value input;
        struct zcl_command_reply reply;
        struct stat st;

        test_make_tmpdir(parent, sizeof(parent), "dev_lane", "badbase");
        (void)snprintf(root, sizeof(root), "%s/root", parent);
        (void)snprintf(lane, sizeof(lane), "%s/lane", parent);
        ASSERT(dln_mkdir_p(root));
        ASSERT(dln_fixture(root));

        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "path", lane);
        (void)json_push_kv_str(&input, "base", "definitely-not-a-ref");
        dln_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "lane.base_unresolved");
        ASSERT(stat(lane, &st) != 0);

        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }
#endif

_test_next:;
    if (failures == 0)
        printf("test_dev_lane: all passed\n");
    else
        printf("test_dev_lane: %d FAILED\n", failures);
    return failures;
}
