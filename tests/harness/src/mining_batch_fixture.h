/* purpose: Exercise a three-block ballot batch on an isolated regtest node. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_TEST_MINING_BATCH_FIXTURE_H
#define ZCL_TEST_MINING_BATCH_FIXTURE_H
#if !defined(_WIN32)
#include "test/regtest_node_fixture.h"
#include "services/miner_signal_round.h"

static const char mining_batch_manifest[] =
    "[\"1111111111111111111111111111111111111111111111111111111111111111\",12,5,"
    "[[\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",18],"
    "[\"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\",19]]]";

static bool mining_batch_catalog(struct rnf *e, char digest[65])
{
    struct miner_signal_catalog_pin pin = {0};
    char dir[PATH_MAX + 64], ballots[PATH_MAX + 96], path[PATH_MAX + 180];
    chain_params_select(CHAIN_REGTEST);
    bool ok = mining_slots_pin(&pin);
    chain_params_select(CHAIN_MAIN);
    zcl_hex_encode(pin.digest, 32, digest);
    snprintf(dir, sizeof(dir), "%s/datadir", e->work);
    snprintf(ballots, sizeof(ballots), "%s/ballots", dir);
    snprintf(path, sizeof(path), "%s/%s.json", ballots, digest);
    if (!ok || mkdir(ballots, 0700) != 0) return false;
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    ok = fwrite(mining_batch_manifest, 1, sizeof(mining_batch_manifest) - 1, f) ==
         sizeof(mining_batch_manifest) - 1;
    return fclose(f) == 0 && ok;
}

static bool mining_batch_start(struct rnf *e, const char *digest)
{
    char p2p[32], pin[96], log[PATH_MAX + 16];
    snprintf(p2p, sizeof(p2p), "-port=%u", e->port[0]);
    snprintf(pin, sizeof(pin), "-testballotcatalog=%s", digest);
    snprintf(log, sizeof(log), "%s/node.log", e->work);
    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (!rnf_child_die_with_parent(parent)) _exit(127);
        setpgid(0, 0);
        int fd = open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd < 0) _exit(127);
        dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO); close(fd);
        setenv("HOME", e->work, 1);
        setenv("CREDENTIALS_DIRECTORY", e->cred, 1);
        execl(RNF_BIN, RNF_BIN, e->dd_flag, e->rpc_flag, "-regtest", pin,
              "-operator-lane=dev", "-private-listeners", "-bind=127.0.0.1",
              "-no-tor", p2p, "-connect=127.0.0.1:1", "-packagehost=0",
              "-wallet-no-phrase-backup", "-walletbackup=0", "-nobgvalidation",
              "-nolegacyimport", "-showmetrics=0", (char *)NULL);
        _exit(127);
    }
    setpgid(pid, pid);
    e->node = pid;
    rnf_node_pid = pid;
    rnf_signals_arm();
    return true;
}

static bool mining_batch_up(struct rnf *e)
{
    char raw[4096];
    const char *const words[] = {"getblockcount", NULL};
    for (int i = 0; i < 240; ++i) {
        int status;
        if (waitpid(e->node, &status, WNOHANG) == e->node) { e->node = 0; return false; }
        if (rnf_exec(e, words, raw, sizeof(raw)) == 0) return true;
        rnf_sleep_ms(500);
    }
    return false;
}

static bool mining_batch_fund(struct rnf *e, const char *address)
{
    char raw[RNF_RAW];
    const char *const ten[] = {"generatetoaddress", "10", address, NULL};
    const char *const one[] = {"generatetoaddress", "1", address, NULL};
    const char *const count[] = {"getblockcount", NULL};
    return rnf_exec(e, ten, raw, sizeof(raw)) == 0 &&
           rnf_exec(e, one, raw, sizeof(raw)) == 0 &&
           rnf_exec(e, count, raw, sizeof(raw)) == 0 && atoi(raw) == 11;
}

static bool mining_batch_coinbase(const struct block *block, const char *hash,
                                  const uint8_t expected[MINER_SIGNAL_SCRIPT_BYTES])
{
    if (!block->num_vtx || !block->vtx[0].num_vout) return false;
    struct uint256 actual;
    char actual_hex[65];
    block_get_hash(block, &actual);
    uint256_get_hex(&actual, actual_hex);
    const struct tx_out *out = &block->vtx[0].vout[block->vtx[0].num_vout - 1];
    return !strcmp(actual_hex, hash) && out->value == 0 &&
           out->script_pub_key.size == MINER_SIGNAL_SCRIPT_BYTES &&
           !memcmp(out->script_pub_key.data, expected, MINER_SIGNAL_SCRIPT_BYTES);
}

static bool mining_batch_block(struct rnf *e, const char *hash, int height,
                               const uint8_t expected[MINER_SIGNAL_SCRIPT_BYTES])
{
    char raw[RNF_RAW], h[16];
    snprintf(h, sizeof(h), "%d", height);
    const char *const by_height[] = {"getblockhash", h, NULL};
    if (rnf_exec(e, by_height, raw, sizeof(raw)) != 0) return false;
    raw[strcspn(raw, "\r\n")] = '\0';
    if (strcmp(raw, hash)) return false;
    const char *const get[] = {"getblock", hash, "0", NULL};
    if (rnf_exec(e, get, raw, sizeof(raw)) != 0) return false;
    raw[strcspn(raw, "\r\n")] = '\0';
    size_t length = strlen(raw);
    if (!length || (length & 1)) return false;
    uint8_t *bytes = malloc(length / 2);
    if (!bytes) return false;
    struct byte_stream stream;
    struct block block;
    block_init(&block);
    bool ok = zcl_hex_decode(raw, bytes, length / 2);
    stream_init_from_data(&stream, bytes, length / 2);
    ok = ok && block_deserialize(&block, &stream) && mining_batch_coinbase(&block, hash, expected);
    block_free(&block);
    stream_free(&stream);
    free(bytes);
    return ok;
}

static bool mining_batch_verify(struct rnf *e, const char *address, const char *digest)
{
    char raw[RNF_RAW], ballot[160];
    snprintf(ballot, sizeof(ballot), "{\"catalog\":\"%s\",\"slots\":[0,1]}", digest);
    const char *const mine[] = {"generatetoaddress", "3", address, ballot, NULL};
    struct json_value hashes = {0};
    bool ok = rnf_exec(e, mine, raw, sizeof(raw)) == 0 &&
              json_read(&hashes, raw, strlen(raw)) && hashes.type == JSON_ARR &&
              json_size(&hashes) == 3;
    uint8_t catalog[32], bits[32] = {3}, expected[MINER_SIGNAL_SCRIPT_BYTES];
    ok = ok && zcl_hex_decode_lower(digest, catalog, sizeof(catalog));
    if (ok) miner_signal_ballot_script(catalog, bits, expected);
    if (ok) {
        bool all = true;
        for (size_t i = 0; i < 3; ++i) {
            bool checked = mining_batch_block(e, json_get_str(json_at(&hashes, i)), (int)i + 12, expected);
            printf("mining batch: block %zu ballot... %s\n", i + 1, checked ? "OK" : "FAIL");
            if (!checked) all = false;
        }
        ok = all;
    }
    json_free(&hashes);
    const char *const count[] = {"getblockcount", NULL};
    return ok && rnf_exec(e, count, raw, sizeof(raw)) == 0 && atoi(raw) == 14;
}

static bool mining_batch_ports_valid(const struct rnf *e)
{
    return e->port[0] && e->port[1] && e->port[0] != 28023 && e->port[0] != 28033 &&
           e->port[1] != 28023 && e->port[1] != 28033;
}

static bool mining_batch_run(struct rnf *e, char digest[65])
{
    if (!rnf_setup(e, "mining_batch") || !mining_batch_ports_valid(e) ||
        !mining_batch_catalog(e, digest)) return false;
    if (setenv("HOME", e->work, 1) != 0 ||
        setenv("CREDENTIALS_DIRECTORY", e->cred, 1) != 0) return false;
    if (!mining_batch_start(e, digest) || !mining_batch_up(e)) return false;
    const char *address = "tmQMh5UwwJGfi53XvgjVZjTGo6SzZGVz6Q6";
    return mining_batch_fund(e, address) && mining_batch_verify(e, address, digest);
}

static bool mining_batch_real_node(void)
{
    struct rnf e = {0};
    char digest[65];
    const char *old_home = getenv("HOME"), *old_cred = getenv("CREDENTIALS_DIRECTORY");
    char *home = old_home ? strdup(old_home) : NULL;
    char *cred = old_cred ? strdup(old_cred) : NULL;
    if ((old_home && !home) || (old_cred && !cred)) { free(home); free(cred); return false; }
    bool ok = mining_batch_run(&e, digest);
    if (!ok && e.work[0]) rnf_log_tail(&e);
    rnf_cleanup(&e);
    if (home) setenv("HOME", home, 1); else unsetenv("HOME");
    if (cred) setenv("CREDENTIALS_DIRECTORY", cred, 1); else unsetenv("CREDENTIALS_DIRECTORY");
    free(home); free(cred);
    return ok;
}
#endif
#endif
