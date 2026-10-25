/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for the C8 parity producer (tools/command/native_fleet_parity.c).
 * The sample is built through an injected RPC function, so two fake nodes
 * stand in for the endpoints: match, mismatch, one side failing, a short
 * chain, the ledger line, the append that never truncates, and a held lock.
 * The leaf itself runs against cookie directories that do not exist, so the
 * node RPC client answers with its error body and no socket is opened.
 */

#include "test/test_core.h"

#include "command/native_fleet_parity.h"
#include "json/json.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#define HASH_A "00000000000000000000000000000000000000000000000000000000000000aa"
#define HASH_B "00000000000000000000000000000000000000000000000000000000000000bb"

struct fake_node {
    int64_t tip;
    const char *hash;  /* NULL: the node answers with an error body */
    bool down;         /* NULL reply: nothing answered */
};

struct fake {
    struct fake_node node[2];
    int64_t asked_height;
};

static int fp_check(bool ok, const char *what)
{
    printf("fleet_parity: %s... %s\n", what, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static char *fake_rpc(void *ctx, int side, const char *method,
                      const char *params)
{
    struct fake *f = ctx;
    const struct fake_node *n = &f->node[side];
    char buf[160];
    if (n->down)
        return NULL;
    if (strcmp(method, "getblockcount") == 0) {
        (void)snprintf(buf, sizeof(buf), "%lld", (long long)n->tip);
        return strdup(buf);
    }
    if (params)
        f->asked_height = atoll(params + 1);
    if (!n->hash)
        return strdup("{\"code\":-8,\"message\":\"Block height out of range\"}");
    (void)snprintf(buf, sizeof(buf), "\"%s\"", n->hash);
    return strdup(buf);
}

static struct fake fake_pair(int64_t tip_a, int64_t tip_b, const char *ha,
                             const char *hb)
{
    struct fake f = { { { tip_a, ha, false }, { tip_b, hb, false } }, -1 };
    return f;
}

static int fp_case_match(void)
{
    struct fake f = fake_pair(5000, 4800, HASH_A, HASH_A);
    struct zcl_parity_sample s;
    int failures = 0;
    zcl_parity_take(fake_rpc, &f, 1700000000, &s);
    failures += fp_check(s.ok && s.match, "equal hashes are a match");
    failures += fp_check(s.height == 4700 && f.asked_height == 4700,
                         "height is min(tips) - 100 and is the one asked");
    failures += fp_check(strcmp(s.our_hash, HASH_A) == 0 &&
                             strcmp(s.oracle_hash, HASH_A) == 0 &&
                             s.ts == 1700000000,
                         "the sample carries both hashes and the clock");
    return failures;
}

static int fp_case_mismatch(void)
{
    struct fake f = fake_pair(1000, 1000, HASH_A, HASH_B);
    struct zcl_parity_sample s;
    zcl_parity_take(fake_rpc, &f, 1, &s);
    return fp_check(s.ok && !s.match && s.height == 900,
                    "different hashes are ok:true match:false");
}

static int fp_case_failures(void)
{
    struct zcl_parity_sample s;
    struct fake f = fake_pair(1000, 1000, HASH_A, NULL);
    int failures = 0;
    zcl_parity_take(fake_rpc, &f, 1, &s);
    failures += fp_check(!s.ok && !s.our_hash[0] && !s.oracle_hash[0],
                         "one side's error body is a hole with no hashes");
    f = fake_pair(1000, 1000, HASH_A, HASH_A);
    f.node[1].down = true;
    zcl_parity_take(fake_rpc, &f, 1, &s);
    failures += fp_check(!s.ok && s.height == -1, "a node that is down is a hole");
    f = fake_pair(1000, 1000, HASH_A, "not-a-hash");
    zcl_parity_take(fake_rpc, &f, 1, &s);
    failures += fp_check(!s.ok && !s.oracle_hash[0], "a malformed hash is a hole");
    f = fake_pair(60, 900, HASH_A, HASH_A);
    zcl_parity_take(fake_rpc, &f, 1, &s);
    failures += fp_check(!s.ok && s.height == -1,
                         "a chain shorter than the margin is a hole");
    return failures;
}

static int fp_case_line(void)
{
    struct fake f = fake_pair(1000, 1000, HASH_A, HASH_B);
    struct zcl_parity_sample s;
    char line[ZCL_PARITY_LINE_MAX];
    size_t len = 0;
    int failures = 0;
    zcl_parity_take(fake_rpc, &f, 7, &s);
    failures += fp_check(zcl_parity_line(&s, line, sizeof(line), &len) &&
                             line[len - 1] == '\n' && len < sizeof(line),
                         "the line ends in a newline");
    line[len - 1] = '\0';
    failures += fp_check(strstr(line, "\"match\":false") &&
                             strstr(line, "\"ok\":true") &&
                             strstr(line, "\"source\":\"rpc-getblockhash\"") &&
                             strstr(line, "\"height\":900"),
                         "the line has the declared keys");
    f.node[0].down = true;
    zcl_parity_take(fake_rpc, &f, 7, &s);
    failures += fp_check(zcl_parity_line(&s, line, sizeof(line), &len), "hole line");
    line[len - 1] = '\0';
    failures += fp_check(strstr(line, "\"our_hash\":null") &&
                             strstr(line, "\"oracle_hash\":null") &&
                             strstr(line, "\"match\":null") &&
                             strstr(line, "\"ok\":false"),
                         "a hole carries nulls and ok:false");
    return failures;
}

static bool fp_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f)
        return false;
    n = fread(buf, 1, cap - 1, f);
    (void)fclose(f);
    buf[n] = '\0';
    return true;
}

static int fp_case_append(void)
{
    char dir[512], file[600], lock[600], text[256];
    const char *why = "";
    int fd, failures = 0;
    test_make_tmpdir(dir, sizeof(dir), "fleet_parity", "append");
    (void)snprintf(file, sizeof(file), "%s/parity.jsonl", dir);
    (void)snprintf(lock, sizeof(lock), "%s/parity.lock", dir);
    fd = open(file, O_WRONLY | O_CREAT, 0600);
    failures += fp_check(fd >= 0 && write(fd, "old\n", 4) == 4,
                         "a ledger with an earlier line");
    if (fd >= 0)
        (void)close(fd);
    failures += fp_check(zcl_parity_append(dir, "one\n", 4, &why) &&
                             zcl_parity_append(dir, "two\n", 4, &why),
                         "two appends succeed");
    failures += fp_check(fp_slurp(file, text, sizeof(text)) &&
                             strcmp(text, "old\none\ntwo\n") == 0,
                         "appends keep the earlier line and the order");
    fd = open(lock, O_RDWR | O_CREAT, 0600);
    failures += fp_check(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0,
                         "another writer holds the lock");
    failures += fp_check(!zcl_parity_append(dir, "three\n", 6, &why) &&
                             strstr(why, "locked"),
                         "a held lock is refused by name");
    failures += fp_check(fp_slurp(file, text, sizeof(text)) &&
                             strcmp(text, "old\none\ntwo\n") == 0,
                         "a refused append writes nothing");
    if (fd >= 0)
        (void)close(fd);
    failures += fp_check(zcl_parity_append(dir, "three\n", 6, &why),
                         "the append succeeds once the lock is released");
    return failures;
}

static bool leaf_run(struct zcl_command_reply *reply, const char *dir,
                     const char *a_port)
{
    struct json_value in;
    struct zcl_command_request request;
    bool ok;
    memset(&request, 0, sizeof(request));
    json_init(&in);
    json_set_object(&in);
    ok = json_push_kv_str(&in, "a_port", a_port) &&
         json_push_kv_int(&in, "b_port", 8232) &&
         json_push_kv_str(&in, "a_cookie_dir", "/nonexistent/parity-a") &&
         json_push_kv_str(&in, "b_cookie_dir", "/nonexistent/parity-b") &&
         json_push_kv_str(&in, "dir", dir);
    request.input = &in;
    if (ok)
        zcl_native_handle_fleet_parity_sample(&request, reply);
    json_free(&in);
    return ok;
}

static int fp_case_leaf(void)
{
    char dir[512], lock[600], file[600], text[512];
    struct zcl_command_reply reply;
    int fd, failures = 0;
    const struct json_value *okv;
    test_make_tmpdir(dir, sizeof(dir), "fleet_parity", "leaf");
    (void)snprintf(file, sizeof(file), "%s/parity.jsonl", dir);
    (void)snprintf(lock, sizeof(lock), "%s/parity.lock", dir);

    zcl_command_reply_init(&reply, "x");
    failures += fp_check(leaf_run(&reply, dir, "70000") &&
                             reply.status != ZCL_COMMAND_STATUS_PASSED &&
                             strcmp(reply.error.code, "PARITY_PORT_INVALID") == 0,
                         "a port out of range is refused by name");
    zcl_command_reply_free(&reply);

    zcl_command_reply_init(&reply, "x");
    okv = leaf_run(&reply, dir, "18242") ? json_get(&reply.data, "ok") : NULL;
    failures += fp_check(reply.status == ZCL_COMMAND_STATUS_PASSED && okv &&
                             !json_get_bool(okv),
                         "an unreachable node is a passed leaf with ok:false");
    failures += fp_check(fp_slurp(file, text, sizeof(text)) &&
                             strstr(text, "\"ok\":false"),
                         "and the hole is in the ledger");
    zcl_command_reply_free(&reply);

    fd = open(lock, O_RDWR | O_CREAT, 0600);
    failures += fp_check(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0, "lock held");
    zcl_command_reply_init(&reply, "x");
    failures += fp_check(leaf_run(&reply, dir, "18242") &&
                             reply.status != ZCL_COMMAND_STATUS_PASSED &&
                             reply.exit_code == ZCL_COMMAND_EXIT_FAILED &&
                             strcmp(reply.error.code, "PARITY_WRITE_FAILED") == 0,
                         "a held lock is an error, not a hole");
    zcl_command_reply_free(&reply);
    if (fd >= 0)
        (void)close(fd);
    return failures;
}

int test_fleet_parity(void);
int test_fleet_parity(void)
{
    int failures = 0;
    failures += fp_case_match();
    failures += fp_case_mismatch();
    failures += fp_case_failures();
    failures += fp_case_line();
    failures += fp_case_append();
    failures += fp_case_leaf();
    if (failures == 0)
        printf("test_fleet_parity: all passed\n");
    else
        printf("test_fleet_parity: %d FAILED\n", failures);
    return failures;
}
