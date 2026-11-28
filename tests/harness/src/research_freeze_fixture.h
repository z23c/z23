/* purpose: Isolated Ironwood node fixture for research-freeze tests. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_RESEARCH_FREEZE_FIXTURE_H
#define ZCL_RESEARCH_FREEZE_FIXTURE_H

#include "test/regtest_node_fixture.h"

static const char rf_digest[] =
    "bb447e1ae3827c976f4ff08a5b5ac7379fa486ce1bc13480f3e9db7e0dc733af";

struct rf_fixture {
    struct rnf node;
    char parent[PATH_MAX + 32], network[PATH_MAX + 64];
    char address[128], shielded[256], restart_shielded[256];
    char deposit_hex[16384];
    char mine_error[4096];
};

static bool rf_file(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(data, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static bool rf_catalog(struct rf_fixture *f)
{
    char marker[PATH_MAX + 128], ballots[PATH_MAX + 128], dest[PATH_MAX + 220];
    snprintf(f->parent, sizeof(f->parent), "%s/datadir", f->node.work);
    snprintf(f->network, sizeof(f->network), "%s/ironwood-research", f->parent);
    snprintf(marker, sizeof(marker), "%s/.z23-research-profile", f->network);
    snprintf(ballots, sizeof(ballots), "%s/ballots", f->network);
    snprintf(dest, sizeof(dest), "%s/%s.json", ballots, rf_digest);
    if (mkdir(f->network, 0700) || mkdir(ballots, 0700)) return false;
    const char identity[] = "z23-research-profile:ironwood:v1\n";
    if (!rf_file(marker, identity, sizeof(identity) - 1)) return false;
    FILE *in = fopen("tests/fixtures/ironwood/selected-manifest.json", "rb");
    if (!in) return false;
    char data[4096];
    size_t n = fread(data, 1, sizeof(data), in);
    bool ok = !ferror(in) && feof(in) && n > 0;
    if (fclose(in)) ok = false;
    return ok && rf_file(dest, data, n);
}

static bool rf_start(struct rf_fixture *f)
{
    char dd[PATH_MAX + 80], p2p[32], rpc[32], pin[96], log[PATH_MAX + 32];
    char home[PATH_MAX + 16], cred[PATH_MAX + 48], params[PATH_MAX + 32];
    snprintf(dd, sizeof(dd), "-datadir=%s", f->parent);
    snprintf(p2p, sizeof(p2p), "-port=%u", f->node.port[0]);
    snprintf(rpc, sizeof(rpc), "-rpcport=%u", f->node.port[1]);
    snprintf(pin, sizeof(pin), "-testballotcatalog=%s", rf_digest);
    snprintf(log, sizeof(log), "%s/node.log", f->node.work);
    snprintf(home, sizeof(home), "HOME=%s", f->node.work);
    snprintf(cred, sizeof(cred), "CREDENTIALS_DIRECTORY=%s", f->node.cred);
    const char *source_home = getenv("HOME");
    if (!source_home || snprintf(params, sizeof(params), "-paramsdir=%s/.zcash-params",
                                 source_home) >= (int)sizeof(params)) return false;
    pid_t parent = getpid(), pid = fork();
    if (pid < 0) return false;
    if (!pid) {
        if (!rnf_child_die_with_parent(parent)) _exit(127);
        setpgid(0, 0);
        int fd = open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd < 0) _exit(127);
        dup2(fd, 1); dup2(fd, 2); close(fd);
        char *const env[] = {home, "PATH=/usr/bin:/bin", cred, NULL};
        execle(RNF_BIN, RNF_BIN, "-testnet-profile=ironwood", pin, dd, p2p, rpc, params,
              "-operator-lane=dev", "-private-listeners", "-bind=127.0.0.1",
              "-no-tor", "-wallet-no-phrase-backup", "-walletbackup=0",
              "-nobgvalidation", "-showmetrics=0", "-packagehost=0",
              "-connect=127.0.0.1:1", (char *)NULL, env);
        _exit(127);
    }
    setpgid(pid, pid);
    f->node.node = pid;
    rnf_node_pid = pid;
    rnf_signals_arm();
    return true;
}

static int rf_rpc(struct rf_fixture *f, const char *const *words, char *out, size_t cap)
{
    char dd[PATH_MAX + 80], home[PATH_MAX + 16], cred[PATH_MAX + 48];
    snprintf(dd, sizeof(dd), "-datadir=%s", f->network);
    snprintf(home, sizeof(home), "HOME=%s", f->node.work);
    snprintf(cred, sizeof(cred), "CREDENTIALS_DIRECTORY=%s", f->node.cred);
    const char *args[RNF_MAX_WORDS + 9] = {
        "/usr/bin/env", "-i", home, "PATH=/usr/bin:/bin", cred, RNF_BIN, dd, f->node.rpc_flag};
    size_t n = 8;
    for (size_t i = 0; words[i] && n < RNF_MAX_WORDS + 8; i++) args[n++] = words[i];
    struct zcl_spawn_evidence ev = {0};
    int rc = zcl_spawn_capture_evidence(args, out, cap, 120000, &ev);
    if (rc < 0 || ev.timed_out) return -1;
    if (!out[0] && ev.stderr_len) rnf_error_line(&ev, out, cap);
    return rc;
}

static bool rf_ready(struct rf_fixture *f)
{
    char raw[4096];
    const char *const words[] = {"getblockcount", NULL};
    long end = rnf_now_ms() + 120000;
    while (rnf_now_ms() < end) {
        int status;
        if (waitpid(f->node.node, &status, WNOHANG) == f->node.node) {
            f->node.node = 0;
            return false;
        }
        if (rf_rpc(f, words, raw, sizeof(raw)) == 0) return true;
        rnf_sleep_ms(500);
    }
    return false;
}

static bool rf_setup(struct rf_fixture *f)
{
    if (!rnf_setup(&f->node, "research_freeze") ||
        !f->node.port[0] || !f->node.port[1] ||
        f->node.port[0] == 28023 || f->node.port[0] == 28033 ||
        f->node.port[1] == 28023 || f->node.port[1] == 28033 ||
        !rf_catalog(f) || !rf_start(f) || !rf_ready(f)) return false;
    char raw[4096];
    const char *const words[] = {"getnewaddress", NULL};
    if (rf_rpc(f, words, raw, sizeof(raw))) return false;
    raw[strcspn(raw, "\r\n")] = 0;
    if (!raw[0] || strlen(raw) >= sizeof(f->address)) return false;
    strcpy(f->address, raw);
    return true;
}

static bool rf_get_height(struct rf_fixture *f, int *height)
{
    char raw[4096], *end;
    const char *const words[] = {"getblockcount", NULL};
    if (rf_rpc(f, words, raw, sizeof(raw))) return false;
    long n = strtol(raw, &end, 10);
    if (end == raw || n < 0 || n > INT_MAX || strspn(end, "\r\n") != strlen(end))
        return false;
    *height = (int)n;
    return true;
}

static bool rf_mine_reply(const char *raw, int count)
{
    struct json_value result = {0};
    bool ok = json_read(&result, raw, strlen(raw)) && result.type == JSON_ARR &&
              json_size(&result) == (size_t)count;
    json_free(&result);
    return ok;
}

/* A timed-out client does not cancel the node's in-flight batch. Wait for
 * that batch to finish instead of issuing overlapping work and overshooting. */
static bool rf_mine_reconcile(struct rf_fixture *f, int *height, int end, const char *reply)
{
    long deadline = rnf_now_ms() + RNF_RECONCILE_MS;
    while (*height < end && rnf_now_ms() < deadline) {
        int current;
        if (rf_get_height(f, &current)) {
            if (current > end || current < *height) break;
            if (current > *height) {
                *height = current;
                deadline = rnf_now_ms() + RNF_RECONCILE_MS;
            }
        }
        if (*height < end) rnf_sleep_ms(200);
    }
    if (*height == end) return true;
    fprintf(stderr, "mine: %s\n", reply);
    return false;
}

static bool rf_mine_batch(struct rf_fixture *f, int *height, int target, bool vote,
                          char *last_error, size_t error_cap)
{
    char n[16], ballot[160], raw[RNF_RAW] = {0};
    int batch = target - *height < 10 ? target - *height : 10;
    int batch_end = *height + batch;
    snprintf(n, sizeof(n), "%d", batch);
    snprintf(ballot, sizeof(ballot), "{\"catalog\":\"%s\",\"slots\":[0,1]}", rf_digest);
    const char *const words[] = {"generatetoaddress", n, f->address, vote ? ballot : NULL, NULL};
    long start = rnf_now_ms();
    int rc = rf_rpc(f, words, raw, sizeof(raw));
    printf("mine-call count=%d vote=%d rc=%d elapsed_ms=%ld\n",
           batch, vote, rc, rnf_now_ms() - start);
    if (!rc && !rf_mine_reply(raw, batch)) {
        fprintf(stderr, "mine: unexpected successful reply: %s\n", raw);
        return false;
    }
    if (rc) snprintf(last_error, error_cap, "%s", raw);
    if (rc && (strstr(raw, "RESPONSE_TIMEOUT") || rc < 0))
        return rf_mine_reconcile(f, height, batch_end, last_error);
    if (rc) return false;
    int current;
    if (!rf_get_height(f, &current))
        return rf_mine_reconcile(f, height, batch_end, rc ? last_error : raw);
    if (current > batch_end || current < *height || current != batch_end)
        return false;
    *height = current;
    return true;
}

static bool rf_mine_progress(int previous, int height, const char *reply)
{
    if (height > previous) return true;
    fprintf(stderr, "mine: %s\n", reply);
    return false;
}

static bool rf_mine(struct rf_fixture *f, int count, bool vote)
{
    char *last_error = f->mine_error;
    last_error[0] = '\0';
    int height;
    if (count <= 0 || !rf_get_height(f, &height) || height > INT_MAX - count) return false;
    int target = height + count;
    long deadline = rnf_now_ms() + RNF_RECONCILE_MS;
    while (height < target && rnf_now_ms() < deadline) {
        int previous = height;
        if (!rf_mine_batch(f, &height, target, vote, last_error, sizeof(f->mine_error))) {
            fprintf(stderr, "mine: %s\n", last_error);
            return false;
        }
        if (!rf_mine_progress(previous, height, last_error)) return false;
        deadline = rnf_now_ms() + RNF_RECONCILE_MS;
    }
    int actual;
    if (height == target && rf_get_height(f, &actual) && actual == target) return true;
    fprintf(stderr, "mine: %s\n", last_error);
    return false;
}

static bool rf_height(struct rf_fixture *f, int height)
{
    int actual;
    return rf_get_height(f, &actual) && actual == height;
}

static bool rf_status(struct rf_fixture *f, int height, int votes, const char *phase)
{
    char raw[RNF_RAW];
    const char *const words[] = {"getballotstatus", NULL};
    if (rf_rpc(f, words, raw, sizeof(raw))) return false;
    printf("ballot status: %s\n", raw);
    struct json_value doc = {0};
    bool ok = json_read(&doc, raw, strlen(raw)) &&
        json_get_bool(json_get(&doc, "rules_bound")) &&
        json_get_int(json_get(&doc, "parent_height")) == height &&
        json_get_int(json_get(&doc, "start")) == 121 &&
        json_get_int(json_get(&doc, "window")) == 20 &&
        json_get_int(json_get(&doc, "required_votes")) == 19;
    const struct json_value *p = json_get(&doc, "proposals");
    for (size_t i = 0; ok && i < 2; i++) {
        const struct json_value *slot = json_at(p, i);
        const char *actual = json_get_str(json_get(slot, "phase_of_next_block"));
        ok = slot && json_get_int(json_get(slot, "slot")) == (int64_t)i &&
            json_get_int(json_get(slot, "activation")) == (int64_t)(143 + i) &&
            json_get_int(json_get(slot, "votes")) == votes &&
            actual && !strcmp(actual, phase);
    }
    json_free(&doc);
    return ok;
}

#endif
