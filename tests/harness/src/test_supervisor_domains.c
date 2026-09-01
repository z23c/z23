/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "json/json.h"
#include "util/supervisor.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define DOM_CHECK(name, expr) do { \
    printf("supervisor_domains: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static void init_contract(struct liveness_contract *c,
                          const char *name,
                          int64_t marker)
{
    liveness_contract_init(c, name);
    atomic_store(&c->progress_marker, marker);
}

int test_supervisor_domains(void)
{
    printf("\n=== supervisor domain tests ===\n");
    int failures = 0;

    supervisor_reset_for_testing();

    supervisor_domain_t *chain = supervisor_create_domain("chain");
    supervisor_domain_t *net = supervisor_create_domain("net");
    supervisor_domain_t *wallet = supervisor_create_domain("wallet");
    supervisor_domain_t *chain_again = supervisor_create_domain("chain");

    DOM_CHECK("create chain domain", chain != NULL);
    DOM_CHECK("create net domain", net != NULL);
    DOM_CHECK("create wallet domain", wallet != NULL);
    DOM_CHECK("duplicate create returns same domain", chain_again == chain);

    static struct liveness_contract chain_a;
    static struct liveness_contract chain_b;
    static struct liveness_contract net_a;
    static struct liveness_contract net_b;
    static struct liveness_contract wallet_a;
    static struct liveness_contract wallet_b;

    init_contract(&chain_a, "domain.chain.a", 10);
    init_contract(&chain_b, "domain.chain.b", 11);
    init_contract(&net_a, "domain.net.a", 20);
    init_contract(&net_b, "domain.net.b", 21);
    init_contract(&wallet_a, "domain.wallet.a", 30);
    init_contract(&wallet_b, "domain.wallet.b", 31);

    DOM_CHECK("register chain.a",
        supervisor_register_in_domain(chain, &chain_a) >= 0);
    DOM_CHECK("register chain.b",
        supervisor_register_in_domain(chain, &chain_b) >= 0);
    DOM_CHECK("register net.a",
        supervisor_register_in_domain(net, &net_a) >= 0);
    DOM_CHECK("register net.b",
        supervisor_register_in_domain(net, &net_b) >= 0);
    DOM_CHECK("register wallet.a",
        supervisor_register_in_domain(wallet, &wallet_a) >= 0);
    DOM_CHECK("register wallet.b",
        supervisor_register_in_domain(wallet, &wallet_b) >= 0);
    DOM_CHECK("NULL domain rejected",
        supervisor_register_in_domain(NULL, &wallet_b) == SUPERVISOR_INVALID_ID);
    DOM_CHECK("total child count is 6", supervisor_child_count_total() == 6);

    struct json_value chain_json;
    json_init(&chain_json);
    DOM_CHECK("domain dump chain returns true",
        supervisor_domain_dump_state_json(chain, &chain_json));
    const struct json_value *chain_name = json_get(&chain_json, "name");
    const struct json_value *chain_count = json_get(&chain_json, "child_count");
    const struct json_value *chain_kids = json_get(&chain_json, "children");
    DOM_CHECK("chain dump has name",
        chain_name && strcmp(json_get_str(chain_name), "chain") == 0);
    DOM_CHECK("chain dump has 2 children",
        chain_count && json_get_int(chain_count) == 2 &&
        chain_kids && json_size(chain_kids) == 2);
    json_free(&chain_json);

    struct json_value all_json;
    json_init(&all_json);
    DOM_CHECK("supervisor dump all domains returns true",
        supervisor_dump_state_json(&all_json, NULL));
    const struct json_value *domains = json_get(&all_json, "domains");
    const struct json_value *orphans = json_get(&all_json, "root_orphans");
    const struct json_value *total = json_get(&all_json, "child_count");
    DOM_CHECK("all dump has 3 domains",
        domains && json_size(domains) == 3);
    DOM_CHECK("all dump has no root orphans",
        orphans && json_size(orphans) == 0);
    DOM_CHECK("all dump total child_count is 6",
        total && json_get_int(total) == 6);
    json_free(&all_json);

    struct json_value one_json;
    json_init(&one_json);
    DOM_CHECK("supervisor dump key=net returns true",
        supervisor_dump_state_json(&one_json, "net"));
    const struct json_value *net_name = json_get(&one_json, "name");
    const struct json_value *net_count = json_get(&one_json, "child_count");
    DOM_CHECK("key dump returns net domain only",
        net_name && strcmp(json_get_str(net_name), "net") == 0 &&
        net_count && json_get_int(net_count) == 2);
    json_free(&one_json);

    supervisor_reset_for_testing();
    return failures;
}
