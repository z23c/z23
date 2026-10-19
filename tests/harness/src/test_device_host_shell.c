/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: fleet usability of the hash-PSK HOST tunnel: the supervised
 * receiver example unit, the --input-file source it reads, psk.new and the
 * injection-proof ssh argv of host.shell. */
#include "test/test_core.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "base/hex.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

extern int repo_path(char *out, size_t outsz, const char *rel);
extern int read_entire_file(const char *path, char **out_buf);

static int shell_receiver_unit(void)
{
    int failures = 0;
    char *unit = NULL, *env = NULL;
    TEST_CASE("device_host_shell: receiver example unit restarts bounded runs") {
        char path[4096];
        ASSERT(repo_path(path, sizeof(path), "platform/deploy/examples/z23-tunnel-receiver.service") == 0);
        ASSERT(read_entire_file(path, &unit) == 0);
        ASSERT(strstr(unit, "\nRestart=always\n") != NULL);
        ASSERT(strstr(unit, "\nRestartSec=2\n") != NULL);
        ASSERT(strstr(unit, "\nNoNewPrivileges=yes\n") != NULL);
        ASSERT(strstr(unit, "\nProtectSystem=strict\n") != NULL);
        /* Lifetime expiry exits 1; refused input (2) must not loop. */
        ASSERT(strstr(unit, "\nSuccessExitStatus=1\n") != NULL);
        ASSERT(strstr(unit, "\nRestartPreventExitStatus=2 3\n") != NULL);
        ASSERT(strstr(unit, "\nEnvironmentFile=%h/") != NULL);
        ASSERT(strstr(unit, "\nEnvironmentFile=-") == NULL);
        ASSERT(strstr(unit, " ops mesh device host receiver --input-file=${Z23_TUNNEL_RECEIVER_INPUT}\n") != NULL);
        ASSERT(repo_path(path, sizeof(path), "platform/deploy/examples/z23-tunnel-receiver.env.example") == 0);
        ASSERT(read_entire_file(path, &env) == 0);
        ASSERT(strstr(env, "\"lifetime_ms\":600000") != NULL);
        ASSERT(strstr(env, "\"max_sessions\":64") != NULL);
        ASSERT(strstr(env, "\"max_active\":4") != NULL);
        ASSERT(strstr(env, "\nZ23_TUNNEL_RECEIVER_INPUT=<HOME>/") != NULL);
    } TEST_END
    free(unit); free(env);
    return failures;
}

#if defined(__linux__) || defined(__APPLE__)
static bool shell_write(const char *path, const char *text, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t length = strlen(text);
    bool ok = write(fd, text, length) == (ssize_t)length && fchmod(fd, mode) == 0;
    return close(fd) == 0 && ok;
}

static int shell_input_file(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_host_shell: --input-file reads only an owner regular file") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-input"));
        char good[1200], link[1200], wide[1200], big[1200], text[64];
        size_t length = 99;
        snprintf(good, sizeof(good), "%s/route.json", directory);
        ASSERT(shell_write(good, "{\"a\":1}\n", 0600));
        ASSERT(zcl_native_device_host_input_file_read(good, text, sizeof(text), &length));
        ASSERT_EQ(length, 7u); ASSERT_STR_EQ(text, "{\"a\":1}");
        ASSERT(!zcl_native_device_host_input_file_read("route.json", text, sizeof(text), &length));
        ASSERT_EQ(length, 0u);
        snprintf(link, sizeof(link), "%s/link.json", directory);
        ASSERT(symlink(good, link) == 0);
        ASSERT(!zcl_native_device_host_input_file_read(link, text, sizeof(text), &length));
        ASSERT(!zcl_native_device_host_input_file_read(directory, text, sizeof(text), &length));
        snprintf(wide, sizeof(wide), "%s/wide.json", directory);
        ASSERT(shell_write(wide, "{\"a\":1}", 0622));
        ASSERT(!zcl_native_device_host_input_file_read(wide, text, sizeof(text), &length));
        snprintf(big, sizeof(big), "%s/big.json", directory);
        ASSERT(shell_write(big, "{\"a\":\"0123456789012345678901234567890123456789012345678901234567\"}", 0600));
        ASSERT(!zcl_native_device_host_input_file_read(big, text, sizeof(text), &length));
        ASSERT_STR_EQ(text, "");
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static void input_rewrite_same_length(const char *path)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd >= 0) { (void)!write(fd, "{\"a\":2}", 7); close(fd); }
}

static void input_chmod_group_read(const char *path)
{
    (void)chmod(path, 0640);
}

static int shell_input_file_rewrite(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_host_shell: --input-file refuses a same-length rewrite or mode change mid-read") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-input-rw"));
        char path[1200], text[64];
        size_t length = 0;
        snprintf(path, sizeof(path), "%s/route.json", directory);
        const struct timespec past[2] = {{.tv_sec = 1000000000}, {.tv_sec = 1000000000}};
        ASSERT(shell_write(path, "{\"a\":1}", 0600));
        ASSERT(utimensat(AT_FDCWD, path, past, 0) == 0);
        /* Control: the hook seam alone, doing nothing, changes no verdict. */
        ASSERT(zcl_native_device_host_input_file_read(path, text, sizeof(text), &length));
        zcl_native_device_host_input_file_hook_for_test(input_rewrite_same_length);
        bool refused = !zcl_native_device_host_input_file_read(path, text, sizeof(text), &length);
        zcl_native_device_host_input_file_hook_for_test(NULL);
        ASSERT(refused);
        ASSERT_EQ(length, 0u); ASSERT_STR_EQ(text, "");
        ASSERT(shell_write(path, "{\"a\":1}", 0600));
        ASSERT(utimensat(AT_FDCWD, path, past, 0) == 0);
        zcl_native_device_host_input_file_hook_for_test(input_chmod_group_read);
        refused = !zcl_native_device_host_input_file_read(path, text, sizeof(text), &length);
        zcl_native_device_host_input_file_hook_for_test(NULL);
        ASSERT(refused);
    } TEST_END
    zcl_native_device_host_input_file_hook_for_test(NULL);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

#if defined(__linux__)
/* Drive the registered leaf exactly as dispatch would: catalog spec plus one
 * {"key": path} input object. */
static bool psk_new_call(const char *path, struct zcl_command_reply *reply)
{
    zcl_command_reply_init(reply, NULL);
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "ops.mesh.device.psk.new", NULL);
    if (!spec || spec->handler != zcl_native_handle_ops_mesh_device_psk_new) return false;
    struct json_value input = {0};
    json_set_object(&input);
    bool pushed = json_push_kv_str(&input, "key", path);
    reply->data_schema = spec->output_schema ? spec->output_schema : reply->data_schema;
    struct zcl_command_request request = {.spec = spec, .input = &input};
    if (pushed) zcl_native_handle_ops_mesh_device_psk_new(&request, reply);
    json_free(&input);
    return pushed;
}

static const char *psk_reply_str(const struct zcl_command_reply *reply, const char *key)
{
    return json_get_str(json_get(&reply->data, key));
}

static int shell_psk_fingerprint(void)
{
    int failures = 0;
    TEST_CASE("device_host_shell: psk fingerprint is a stable domain-separated SHA3-256 prefix") {
        uint8_t key[32];
        for (size_t i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)i;
        char first[17], second[17], prefix[65];
        zcl_native_device_psk_fingerprint(key, first);
        zcl_native_device_psk_fingerprint(key, second);
        /* openssl dgst -sha3-256 over "z23.device.host.psk.fingerprint.v1\0" || 00..1f */
        ASSERT_STR_EQ(first, "fa5ecb987676c68b");
        ASSERT_STR_EQ(first, second);
        zcl_hex_encode(key, 32, prefix);
        ASSERT(strncmp(first, prefix, 16) != 0);
        key[31] ^= 1;
        zcl_native_device_psk_fingerprint(key, second);
        ASSERT(strcmp(first, second) != 0);
    } TEST_END
    return failures;
}

static int shell_psk_new(void)
{
    int failures = 0;
    char directory[1024] = {0};
    struct zcl_command_reply reply = {0};
    TEST_CASE("device_host_shell: psk.new creates one 0600 32-byte key and refuses reuse or symlink") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-psk"));
        char path[1200], link[1200], target[1200], hex[65];
        snprintf(path, sizeof(path), "%s/host.psk", directory);
        ASSERT(psk_new_call(path, &reply));
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(reply.error.mutated);
        struct stat st;
        ASSERT(lstat(path, &st) == 0);
        ASSERT(S_ISREG(st.st_mode)); ASSERT_EQ(st.st_mode & 0777, 0600u); ASSERT_EQ(st.st_size, 32);
        uint8_t key[32]; char expect[17];
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        ASSERT(fd >= 0);
        ASSERT_EQ(read(fd, key, sizeof(key)), 32); close(fd);
        zcl_native_device_psk_fingerprint(key, expect);
        const char *fingerprint = psk_reply_str(&reply, "psk_fingerprint");
        ASSERT(fingerprint != NULL); ASSERT_STR_EQ(fingerprint, expect);
        zcl_hex_encode(key, 32, hex);
        ASSERT(strncmp(fingerprint, hex, 16) != 0);
        /* The reply names no key bytes and no path. */
        char wire[1024];
        ASSERT(json_write(&reply.data, wire, sizeof(wire)) > 0);
        bool leaked = strstr(wire, hex) != NULL || strstr(wire, "host.psk") != NULL;
        ASSERT(!leaked);
        memset(key, 0, sizeof(key));
        zcl_command_reply_free(&reply); memset(&reply, 0, sizeof(reply));

        ASSERT(psk_new_call(path, &reply));
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "PSK_KEY_EXISTS");
        ASSERT(!reply.error.mutated);
        ASSERT(lstat(path, &st) == 0); ASSERT_EQ(st.st_size, 32);
        zcl_command_reply_free(&reply); memset(&reply, 0, sizeof(reply));

        snprintf(target, sizeof(target), "%s/absent-target", directory);
        snprintf(link, sizeof(link), "%s/link.psk", directory);
        ASSERT(symlink(target, link) == 0);
        ASSERT(psk_new_call(link, &reply));
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "PSK_KEY_EXISTS");
        ASSERT(lstat(target, &st) != 0);
        zcl_command_reply_free(&reply); memset(&reply, 0, sizeof(reply));

        ASSERT(chmod(directory, 0755) == 0);
        snprintf(path, sizeof(path), "%s/open.psk", directory);
        ASSERT(psk_new_call(path, &reply));
        ASSERT_STR_EQ(reply.error.code, "PSK_KEY_PARENT_NOT_PRIVATE");
        ASSERT(lstat(path, &st) != 0);
        ASSERT(chmod(directory, 0700) == 0);
    } TEST_END
    zcl_command_reply_free(&reply);
    if (directory[0]) { (void)chmod(directory, 0700); test_rm_rf(directory); }
    return failures;
}

static int shell_psk_cleanup_honesty(void)
{
    int failures = 0;
    char directory[1024] = {0};
    struct zcl_command_reply reply = {0};
    TEST_CASE("device_host_shell: psk.new never claims no key left when cleanup fails") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-psk-io"));
        char gone[1200], left[1200];
        struct stat st;
        snprintf(gone, sizeof(gone), "%s/gone.psk", directory);
        snprintf(left, sizeof(left), "%s/left.psk", directory);
        /* Write fails, unlink works: the file is really gone. */
        zcl_native_device_psk_fault_for_test(1u);
        ASSERT(psk_new_call(gone, &reply));
        ASSERT_STR_EQ(reply.error.code, "PSK_KEY_IO");
        ASSERT(!reply.error.mutated);
        ASSERT(lstat(gone, &st) != 0);
        zcl_command_reply_free(&reply); memset(&reply, 0, sizeof(reply));
        /* Write and unlink both fail: a file remains, so the reply says so. */
        zcl_native_device_psk_fault_for_test(3u);
        ASSERT(psk_new_call(left, &reply));
        zcl_native_device_psk_fault_for_test(0);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "PSK_KEY_CLEANUP_UNCERTAIN");
        ASSERT(reply.error.mutated);
        ASSERT(lstat(left, &st) == 0);
    } TEST_END
    zcl_native_device_psk_fault_for_test(0);
    zcl_command_reply_free(&reply);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

#endif
static bool shell_argv_equal(const struct zcl_native_host_shell_argv *plan, const char *const *want, size_t count)
{
    if (plan->argc != count || plan->argv[count] != NULL) return false;
    for (size_t i = 0; i < count; ++i) if (!plan->argv[i] || strcmp(plan->argv[i], want[i])) return false;
    return true;
}

static int shell_dry_run_argv(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_host_shell: dry_run argv is the exact fixed ssh vector") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-shell"));
        char route[1200], proxy[2400];
        snprintf(route, sizeof(route), "%s/route.json", directory);
        ASSERT(shell_write(route, "{}", 0600));
        snprintf(proxy, sizeof(proxy), "ProxyCommand=/opt/z23/bin/z23 ops mesh device host client --input-file=%s", route);
        struct zcl_native_host_shell_argv plan; const char *refusal = "unset";
        ASSERT(zcl_native_device_host_shell_argv("/opt/z23/bin/z23", "alice", "r2.lan", route, false, &plan, &refusal));
        ASSERT(refusal == NULL);
        const char *const sntrup[] = {"ssh", "-o", "KexAlgorithms=sntrup761x25519-sha512@openssh.com",
            "-o", "StrictHostKeyChecking=yes", "-o", "ControlPath=none", "-o", proxy, "--", "alice@r2.lan"};
        ASSERT(shell_argv_equal(&plan, sntrup, sizeof(sntrup) / sizeof(sntrup[0])));
        ASSERT(zcl_native_device_host_shell_argv("/opt/z23/bin/z23", "alice", "r2.lan", route, true, &plan, &refusal));
        const char *const both[] = {"ssh", "-o", "KexAlgorithms=mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com",
            "-o", "StrictHostKeyChecking=yes", "-o", "ControlPath=none", "-o", proxy, "--", "alice@r2.lan"};
        ASSERT(shell_argv_equal(&plan, both, sizeof(both) / sizeof(both[0])));
        struct json_value out = {0};
        ASSERT(zcl_native_device_host_shell_json(&plan, NULL, "/usr/bin/ssh", &out));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "executable")), "/usr/bin/ssh");
        ASSERT_STR_EQ(json_get_str(json_get(&out, "schema")), "zcl.device.host.shell.v1");
        const struct json_value *list = json_get(&out, "argv");
        bool same = list && list->type == JSON_ARR && list->num_children == plan.argc;
        for (size_t i = 0; same && i < plan.argc; ++i) same = !strcmp(json_get_str(json_at(list, i)), both[i]);
        json_free(&out);
        ASSERT(same);
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static bool shell_script(const char *path, const char *body)
{
    return shell_write(path, body, 0700);
}

static bool shell_route_file(const char *path)
{
    char peer[65], root[65];
    memset(peer, 'a', 64); peer[64] = '\0';
    memset(root, 'b', 64); root[64] = '\0';
    char text[1024];
    snprintf(text, sizeof(text),
        "{\"directory\":\"/var/lib/z23x\",\"peer_key\":\"%s\",\"expected_root\":\"%s\",\"target_port\":22,"
        "\"route_id\":\"PUBLIC-local-loopback\",\"handshake_ms\":5000,\"session_ms\":15000,\"idle_ms\":5000,"
        "\"confirm\":true,\"route_address\":\"127.0.0.1\",\"route_port\":4000,\"connect_ms\":3000}", peer, root);
    return shell_write(path, text, 0600);
}

/* Run the leaf with stdout captured to a file. Returns its exit code. */
static int shell_run_captured(const struct json_value *input, const char *capture)
{
    fflush(stdout);
    int saved = dup(1), file = open(capture, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (saved < 0 || file < 0 || dup2(file, 1) < 0) return -1;
    close(file);
    int code = zcl_native_device_host_shell_run(input);
    fflush(stdout);
    (void)dup2(saved, 1); close(saved);
    return code;
}

static bool shell_run_input(struct json_value *input, const char *route, bool dry)
{
    json_set_object(input);
    return json_push_kv_str(input, "user", "alice") && json_push_kv_str(input, "host", "r2.lan") &&
        json_push_kv_str(input, "route_input", route) && json_push_kv_bool(input, "dry_run", dry);
}

static int shell_dry_run_executes_nothing(void)
{
    int failures = 0;
    char directory[1024] = {0};
    char *prior = getenv("PATH") ? strdup(getenv("PATH")) : NULL;
    TEST_CASE("device_host_shell: dry_run runs no ssh and reports the once-resolved path and both shapes") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-dry"));
        char bin[1200], ssh[1200], marker[1200], route[1200], capture[1200], script[1400];
        snprintf(bin, sizeof(bin), "%s/bin", directory);
        ASSERT(mkdir(bin, 0700) == 0);
        snprintf(ssh, sizeof(ssh), "%s/ssh", bin);
        snprintf(marker, sizeof(marker), "%s/marker", directory);
        snprintf(script, sizeof(script), "#!/bin/sh\n: > %s\nexit 1\n", marker);
        ASSERT(shell_script(ssh, script));
        snprintf(route, sizeof(route), "%s/route.json", directory);
        ASSERT(shell_route_file(route));
        snprintf(capture, sizeof(capture), "%s/out.json", directory);
        ASSERT(setenv("PATH", bin, 1) == 0);
        struct json_value input = {0};
        ASSERT(shell_run_input(&input, route, true));
        int code = shell_run_captured(&input, capture);
        json_free(&input);
        struct stat st;
        bool spawned = lstat(marker, &st) == 0;
        char *out = NULL;
        ASSERT(read_entire_file(capture, &out) == 0);
        ASSERT(!spawned);
        ASSERT_EQ(code, 0);
        ASSERT(strstr(out, "\"kex_probe\":\"skipped\"") != NULL);
        ASSERT(strstr(out, ssh) != NULL);
        ASSERT(strstr(out, "\"argv_mlkem\"") != NULL);
        ASSERT(strstr(out, "KexAlgorithms=sntrup761x25519-sha512@openssh.com\"") != NULL);
        ASSERT(strstr(out, "KexAlgorithms=mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com\"") != NULL);
        free(out);
    } TEST_END
    if (prior) { (void)setenv("PATH", prior, 1); free(prior); }
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static int shell_ssh_resolution(void)
{
    int failures = 0;
    char directory[1024] = {0};
    char *prior = getenv("PATH") ? strdup(getenv("PATH")) : NULL;
    TEST_CASE("device_host_shell: ssh resolves once from absolute PATH entries and relative ones refuse") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-resolve"));
        char bin[1200], plain[1200], ssh[1200], want[1300], list[2600], out[1200], marker[1200], route[1200], script[1400];
        snprintf(bin, sizeof(bin), "%s/bin", directory);
        snprintf(plain, sizeof(plain), "%s/plain", directory);
        ASSERT(mkdir(bin, 0700) == 0); ASSERT(mkdir(plain, 0700) == 0);
        snprintf(ssh, sizeof(ssh), "%s/ssh", bin);
        snprintf(want, sizeof(want), "%s", ssh);
        snprintf(marker, sizeof(marker), "%s/marker", directory);
        snprintf(script, sizeof(script), "#!/bin/sh\n: > %s\nexit 1\n", marker);
        ASSERT(shell_script(ssh, script));
        /* A non-executable ssh earlier on PATH is skipped. */
        char skipped[1200];
        snprintf(skipped, sizeof(skipped), "%s/ssh", plain);
        ASSERT(shell_write(skipped, "x", 0600));
        snprintf(list, sizeof(list), "%s:%s", plain, bin);
        ASSERT(zcl_native_device_host_shell_resolve(list, out, sizeof(out)));
        ASSERT_STR_EQ(out, want);
        ASSERT(!zcl_native_device_host_shell_resolve(plain, out, sizeof(out)));
        /* Relative and empty components refuse the whole PATH, even with a hit. */
        const char *bad[] = {"bin", "./bin", "..", "", ":", NULL};
        for (size_t i = 0; bad[i]; ++i) {
            snprintf(list, sizeof(list), "%s:%s", bad[i], bin);
            ASSERT(!zcl_native_device_host_shell_resolve(list, out, sizeof(out)));
            ASSERT_STR_EQ(out, "");
            snprintf(list, sizeof(list), "%s:%s", bin, bad[i]);
            ASSERT(!zcl_native_device_host_shell_resolve(list, out, sizeof(out)));
        }
        ASSERT(!zcl_native_device_host_shell_resolve(NULL, out, sizeof(out)));
        /* The leaf itself refuses a relative PATH and spawns nothing. */
        snprintf(route, sizeof(route), "%s/route.json", directory);
        ASSERT(shell_route_file(route));
        snprintf(list, sizeof(list), "%s:%s", "relative-bin", bin);
        ASSERT(setenv("PATH", list, 1) == 0);
        struct json_value input = {0};
        ASSERT(shell_run_input(&input, route, true));
        char capture[1200];
        snprintf(capture, sizeof(capture), "%s/out.json", directory);
        int code = shell_run_captured(&input, capture);
        json_free(&input);
        struct stat st;
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_BLOCKED);
        ASSERT(lstat(marker, &st) != 0);
    } TEST_END
    if (prior) { (void)setenv("PATH", prior, 1); free(prior); }
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

struct shell_refusal { const char *user, *host, *route, *self, *field; };

static int shell_injection_refused(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_host_shell: shell, ssh-token and option injection refuse before any argv") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-shell"));
        char route[1200], linked[1200];
        snprintf(route, sizeof(route), "%s/route.json", directory);
        ASSERT(shell_write(route, "{}", 0600));
        snprintf(linked, sizeof(linked), "%s/linked.json", directory);
        ASSERT(symlink(route, linked) == 0);
        const char *self = "/opt/z23/bin/z23";
        const struct shell_refusal cases[] = {
            {"a;id", "h", route, self, "user_refused"}, {"$(id)", "h", route, self, "user_refused"},
            {"`id`", "h", route, self, "user_refused"}, {"a b", "h", route, self, "user_refused"},
            {"a%h", "h", route, self, "user_refused"}, {"a\nb", "h", route, self, "user_refused"},
            {"-oProxyCommand=id", "h", route, self, "user_refused"}, {"", "h", route, self, "user_refused"},
            {"a'b", "h", route, self, "user_refused"}, {"a\"b", "h", route, self, "user_refused"},
            {"u", "h;id", route, self, "host_refused"}, {"u", "$(id)", route, self, "host_refused"},
            {"u", "`id`", route, self, "host_refused"}, {"u", "h h", route, self, "host_refused"},
            {"u", "%h", route, self, "host_refused"}, {"u", "h\n", route, self, "host_refused"},
            {"u", "-oProxyCommand=id", route, self, "host_refused"}, {"u", "a@b", route, self, "host_refused"},
            {"u", "h", "route.json", self, "route_input_refused"},
            {"u", "h", "/x/a;id", self, "route_input_refused"}, {"u", "h", "/x/$(id)", self, "route_input_refused"},
            {"u", "h", "/x/`id`", self, "route_input_refused"}, {"u", "h", "/x/a b", self, "route_input_refused"},
            {"u", "h", "/x/%h", self, "route_input_refused"}, {"u", "h", "/x/a\nb", self, "route_input_refused"},
            {"u", "h", "/x/'q'", self, "route_input_refused"},
            {"u", "h", directory, self, "route_input_refused"}, {"u", "h", linked, self, "route_input_refused"},
            {"u", "h", "/nonexistent/route.json", self, "route_input_refused"},
            {"u", "h", route, "/opt/z23/bin/z23 (deleted)", "self_refused"},
            {"u", "h", route, "z23", "self_refused"}, {"u", "h", route, "/opt/$(id)/z23", "self_refused"},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            struct zcl_native_host_shell_argv plan; const char *refusal = NULL;
            bool built = zcl_native_device_host_shell_argv(cases[i].self, cases[i].user, cases[i].host,
                cases[i].route, false, &plan, &refusal);
            if (built || !refusal || strcmp(refusal, cases[i].field) || plan.argc != 0)
                printf("injection case %zu admitted (refusal=%s)\n", i, refusal ? refusal : "none");
            ASSERT(!built); ASSERT(refusal != NULL); ASSERT_STR_EQ(refusal, cases[i].field); ASSERT_EQ(plan.argc, 0u);
        }
        char longest[300]; memset(longest, 'a', sizeof(longest) - 1); longest[sizeof(longest) - 1] = '\0';
        struct zcl_native_host_shell_argv plan; const char *refusal = NULL;
        ASSERT(!zcl_native_device_host_shell_argv(self, "u", longest, route, false, &plan, &refusal));
        ASSERT_STR_EQ(refusal, "host_refused");
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

#if defined(__linux__)
static int shell_package_hangup_race(void)
{
    int failures = 0;
    TEST_CASE("device_host_shell: a hangup that races the engine exit reports the observed exit") {
        /* ssh HUPs its ProxyCommand as the session ends; an engine already
         * exiting cannot take the forward, and that is not a failure. */
        ASSERT_STR_EQ(zcl_native_device_host_package_hangup_for_test(true), "observed_exit");
        /* A still-running engine that cannot be signalled stays named. */
        ASSERT_STR_EQ(zcl_native_device_host_package_hangup_for_test(false), "signal_queue_failed");
    } TEST_END
    return failures;
}
#endif
#endif

#if defined(__linux__) || defined(__APPLE__)
static int shell_route_check_refusals(void)
{
    int failures = 0;
    char directory[1024] = {0}, route[1200];
    TEST_CASE("device_host_shell: route_check refuses relative, missing and non-client routes offline") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-shell-route"));
        snprintf(route, sizeof(route), "%s/route.json", directory);
        ASSERT(!strcmp(zcl_native_device_host_shell_route_check("route.json", 1), "route_input_refused"));
        ASSERT(!strcmp(zcl_native_device_host_shell_route_check(route, 1), "route_input_refused"));
        ASSERT(shell_write(route, "{}", 0600));
        ASSERT(!strcmp(zcl_native_device_host_shell_route_check(route, 1), "route_input_not_a_client_input"));
    } TEST_END
    return failures;
}

#endif

int test_device_host_shell(void);
int test_device_host_shell(void)
{
    int failures = shell_receiver_unit();
#if defined(__linux__) || defined(__APPLE__)
    failures += shell_input_file() + shell_input_file_rewrite();
    failures += shell_route_check_refusals();
    failures += shell_dry_run_argv() + shell_dry_run_executes_nothing() + shell_ssh_resolution() + shell_injection_refused();
#if defined(__linux__)
    failures += shell_psk_fingerprint() + shell_psk_new() + shell_psk_cleanup_honesty() + shell_package_hangup_race();
#endif
#endif
    return failures;
}
