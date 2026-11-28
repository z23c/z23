/* purpose: Exercise research rules on an isolated Ironwood node. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "research_freeze_fixture.h"

#define RF_CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "research_freeze_node:%d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static int rf_schedule(struct rf_fixture *f)
{
    RF_CHECK(rf_height(f, 0));
    RF_CHECK(rf_mine(f, 119, false));
    RF_CHECK(rf_height(f, 119));
    char raw[RNF_RAW], ballot[160];
    snprintf(ballot, sizeof(ballot), "{\"catalog\":\"%s\",\"slots\":[0,1]}", rf_digest);
    const char *const early[] = {"generatetoaddress", "1", f->address, ballot, NULL};
    RF_CHECK(rf_rpc(f, early, raw, sizeof(raw)) != 0);
    RF_CHECK(strstr(raw, "Template height outside the pinned voting window"));
    RF_CHECK(rf_height(f, 119));
    RF_CHECK(rf_mine(f, 1, false));
    for (int h = 121; h <= 140; ++h) {
        RF_CHECK(rf_mine(f, 1, h != 130));
        RF_CHECK(rf_height(f, h));
        RF_CHECK(rf_status(f, h, h - 120 - (h >= 130), h == 140 ? "locked_in" : "voting"));
    }
    RF_CHECK(rf_mine(f, 6, false));
    RF_CHECK(rf_height(f, 146));
    RF_CHECK(rf_status(f, 146, 19, "active"));
    return 0;
}

static int rf_mature_reward(struct rf_fixture *f)
{
    char raw[RNF_RAW], address[128], recipients[256];
    const char *const new_address[] = {"getnewaddress", NULL};
    RF_CHECK(rf_height(f, 0));
    RF_CHECK(rf_rpc(f, new_address, raw, sizeof(raw)) == 0);
    raw[strcspn(raw, "\r\n")] = 0;
    RF_CHECK(raw[0] && strlen(raw) < sizeof(address));
    strcpy(address, raw);
    snprintf(recipients, sizeof(recipients), "[{\"address\":\"%s\",\"amount\":1}]", address);
    const char *const send[] = {"z_sendmany", f->address, recipients, NULL};
    RF_CHECK(rf_mine(f, 100, false));
    RF_CHECK(rf_height(f, 100));
    int rc = rf_rpc(f, send, raw, sizeof(raw));
    printf("immature reward reply (rc=%d): %s\n", rc, raw);
    RF_CHECK(rc != 0);
    RF_CHECK(rf_mine(f, 1, false));
    RF_CHECK(rf_height(f, 101));
    rc = rf_rpc(f, send, raw, sizeof(raw));
    printf("mature reward reply (rc=%d): %s\n", rc, raw);
    RF_CHECK(rc == 0);
    RF_CHECK(rf_mine(f, 1, false));
    RF_CHECK(rf_height(f, 102));
    const char *const balance[] = {"z_getbalance", address, NULL};
    RF_CHECK(rf_rpc(f, balance, raw, sizeof(raw)) == 0);
    RF_CHECK(rnf_zats(raw) == 100000000);
    return 0;
}

static int rf_deposit_before(struct rf_fixture *f)
{
    char raw[RNF_RAW], recipients[800];
    const char *const address[] = {"z_getnewaddress", NULL};
    RF_CHECK(rf_height(f, 102));
    RF_CHECK(rf_rpc(f, address, raw, sizeof(raw)) == 0);
    raw[strcspn(raw, "\r\n")] = 0;
    RF_CHECK(raw[0] && strlen(raw) < sizeof(f->shielded));
    strcpy(f->shielded, raw);
    RF_CHECK(rf_rpc(f, address, raw, sizeof(raw)) == 0);
    raw[strcspn(raw, "\r\n")] = 0;
    RF_CHECK(raw[0] && strlen(raw) < sizeof(f->restart_shielded));
    strcpy(f->restart_shielded, raw);
    snprintf(recipients, sizeof(recipients),
             "[{\"address\":\"%s\",\"amount\":1},{\"address\":\"%s\",\"amount\":1}]",
             f->shielded, f->restart_shielded);
    const char *const send[] = {"z_sendmany", f->address, recipients, NULL};
    int rc = rf_rpc(f, send, raw, sizeof(raw));
    printf("pre-freeze deposit reply (rc=%d): %s\n", rc, raw);
    RF_CHECK(rc == 0);
    raw[strcspn(raw, "\r\n")] = 0;
    char txid[80];
    RF_CHECK(strlen(raw) == 64);
    strcpy(txid, raw);
    RF_CHECK(rf_mine(f, 1, false));
    const char *const get_tx[] = {"getrawtransaction", txid, NULL};
    RF_CHECK(rf_rpc(f, get_tx, raw, sizeof(raw)) == 0);
    raw[strcspn(raw, "\r\n")] = 0;
    RF_CHECK(raw[0] && strlen(raw) < sizeof(f->deposit_hex));
    strcpy(f->deposit_hex, raw);
    const char *const balance[] = {"z_getbalance", f->shielded, NULL};
    RF_CHECK(rf_rpc(f, balance, raw, sizeof(raw)) == 0);
    RF_CHECK(rnf_zats(raw) == 100000000);
    const char *const restart_balance[] = {"z_getbalance", f->restart_shielded, NULL};
    RF_CHECK(rf_rpc(f, restart_balance, raw, sizeof(raw)) == 0);
    RF_CHECK(rnf_zats(raw) == 100000000);
    return 0;
}

static int rf_activate(struct rf_fixture *f)
{
    RF_CHECK(rf_height(f, 103));
    RF_CHECK(rf_mine(f, 17, false));
    for (int h = 121; h <= 140; h++)
        RF_CHECK(rf_mine(f, 1, h != 130));
    RF_CHECK(rf_status(f, 140, 19, "locked_in"));
    RF_CHECK(rf_mine(f, 6, false));
    RF_CHECK(rf_height(f, 146));
    RF_CHECK(rf_status(f, 146, 19, "active"));
    return 0;
}

static int rf_refuse_send(struct rf_fixture *f, int height)
{
    char raw[RNF_RAW], before[RNF_RAW], recipients[400];
    const char *const pool[] = {"getrawmempool", NULL};
    RF_CHECK(rf_height(f, height));
    RF_CHECK(rf_status(f, height, 19, "active"));
    RF_CHECK(rf_rpc(f, pool, before, sizeof(before)) == 0);
    snprintf(recipients, sizeof(recipients), "[{\"address\":\"%s\",\"amount\":1}]", f->shielded);
    const char *const send[] = {"z_sendmany", f->address, recipients, NULL};
    int rc = rf_rpc(f, send, raw, sizeof(raw));
    printf("frozen send reply (rc=%d): %s\n", rc, raw);
    RF_CHECK(rc != 0 && strstr(raw, "research-deposit-freeze"));
    const char *const raw_send[] = {"sendrawtransaction", f->deposit_hex, NULL};
    rc = rf_rpc(f, raw_send, raw, sizeof(raw));
    printf("frozen raw-send reply (rc=%d): %s\n", rc, raw);
    RF_CHECK(rc != 0 && strstr(raw, "research-deposit-freeze"));
    RF_CHECK(rf_height(f, height));
    RF_CHECK(rf_rpc(f, pool, raw, sizeof(raw)) == 0 && !strcmp(before, raw));
    return 0;
}

static int rf_refuse_shield(struct rf_fixture *f)
{
    char raw[RNF_RAW], input[512], commit[4096], before[RNF_RAW];
    RF_CHECK(rf_height(f, 146));
    RF_CHECK(rf_status(f, 146, 19, "active"));
    const char *const pool[] = {"getrawmempool", NULL};
    RF_CHECK(rf_rpc(f, pool, before, sizeof(before)) == 0);
    snprintf(input, sizeof(input),
             "--input={\"wallet_scope\":\"dev\",\"from\":\"%s\",\"idempotency_key\":\"freeze-shield\"}",
             f->address);
    const char *const plan[] = {"core", "wallet", "shielded", "shield", input, NULL};
    RF_CHECK(rf_rpc(f, plan, raw, sizeof(raw)) == 0);
    struct json_value doc = {0};
    RF_CHECK(json_read(&doc, raw, strlen(raw)));
    const char *ci = rnf_str(&doc, "data.commit_input");
    RF_CHECK(ci[0] && strlen(ci) + 9 < sizeof(commit));
    snprintf(commit, sizeof(commit), "--input=%s", ci);
    json_free(&doc);
    const char *const execute[] = {"core", "wallet", "shielded", "shield", commit, NULL};
    int rc = rf_rpc(f, execute, raw, sizeof(raw));
    printf("frozen shield reply (rc=%d): %s\n", rc, raw);
    RF_CHECK(strstr(raw, "research-deposit-freeze"));
    RF_CHECK(rf_height(f, 146));
    RF_CHECK(rf_rpc(f, pool, raw, sizeof(raw)) == 0 && !strcmp(before, raw));
    return 0;
}

static int rf_withdraw(struct rf_fixture *f, int height, const char *source)
{
    char raw[RNF_RAW], recipients[256], txid[80], count[16];
    RF_CHECK(rf_height(f, height));
    RF_CHECK(rf_status(f, height, 19, "active"));
    snprintf(recipients, sizeof(recipients), "[{\"address\":\"%s\",\"amount\":0.25}]", f->address);
    const char *const send[] = {"z_sendmany", source, recipients, NULL};
    int rc = rf_rpc(f, send, raw, sizeof(raw));
    printf("frozen withdrawal reply (rc=%d): %s\n", rc, raw);
    RF_CHECK(rc == 0);
    raw[strcspn(raw, "\r\n")] = 0;
    RF_CHECK(strlen(raw) == 64);
    strcpy(txid, raw);
    RF_CHECK(rf_mine(f, 1, false));
    RF_CHECK(rf_height(f, height + 1));
    snprintf(count, sizeof(count), "%d", height + 1);
    const char *const hash[] = {"getblockhash", count, NULL};
    RF_CHECK(rf_rpc(f, hash, raw, sizeof(raw)) == 0);
    raw[strcspn(raw, "\r\n")] = 0;
    char blockhash[80];
    RF_CHECK(strlen(raw) == 64);
    strcpy(blockhash, raw);
    const char *const block[] = {"getblock", blockhash, NULL};
    RF_CHECK(rf_rpc(f, block, raw, sizeof(raw)) == 0 && strstr(raw, txid));
    return 0;
}

static int rf_restart(struct rf_fixture *f)
{
    RF_CHECK(rf_height(f, 147));
    RF_CHECK(rf_status(f, 147, 19, "active"));
    rnf_node_stop(&f->node);
    RF_CHECK(rf_start(f) && rf_ready(f));
    RF_CHECK(rf_refuse_send(f, 147) == 0);
    RF_CHECK(rf_withdraw(f, 147, f->restart_shielded) == 0);
    return 0;
}

int test_research_freeze_node(void)
{
    struct rf_fixture f = {0};
    int failures = 0;
    if (!rf_setup(&f)) {
        fprintf(stderr, "research_freeze_node: setup failed\n");
        failures = 1;
    } else {
        failures = rf_schedule(&f);
    }
    if (failures && f.node.work[0]) rnf_log_tail(&f.node);
    rnf_cleanup(&f.node);
    if (!failures) {
        f = (struct rf_fixture){0};
        if (!rf_setup(&f)) failures = 1;
        else failures = rf_mature_reward(&f);
        if (!failures) failures = rf_deposit_before(&f);
        if (!failures) failures = rf_activate(&f);
        if (!failures) failures = rf_refuse_send(&f, 146);
        if (!failures) failures = rf_refuse_shield(&f);
        if (!failures) failures = rf_withdraw(&f, 146, f.shielded);
        if (!failures) failures = rf_restart(&f);
        if (failures && f.node.work[0]) rnf_log_tail(&f.node);
        rnf_cleanup(&f.node);
    }
    return failures;
}
