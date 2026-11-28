/* purpose: Verify explicit research boot consent and process-lifetime binding. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "base/hex.h"
#include "chain/chainparams.h"
#include "config/boot.h"
#include "config/boot_ballot_catalog.h"
#include "consensus/params.h"
#include "json/json.h"
#include "services/research_rules.h"
#include "test/test_core.h"
#include "util/util.h"
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "boot ballot catalog line %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static struct app_context ctx;
static const char manifest[] =
    "[\"1111111111111111111111111111111111111111111111111111111111111111\",100,20,"
    "[[\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",122]]]";

int test_boot_ballot_catalog(void)
{
    const char *empty[] = {"z23"};
    ParseParameters(1, empty);
    chain_params_select(CHAIN_MAIN);
    int main_ow = chain_params_get()->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight;
    int main_sap = chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight;
    chain_params_select(CHAIN_REGTEST);
    int reg_ow = chain_params_get()->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight;
    int reg_sap = chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight;
    CHECK(chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD));
    CHECK(!boot_ballot_catalog_load(&ctx) && !research_rules_binding());
    struct miner_signal_catalog_pin wrong = {0};
    CHECK(!research_rules_install(chain_params_get(), &wrong) && !research_rules_binding());

    struct json_value doc = {0};
    struct miner_signal_catalog_pin pin = {0};
    CHECK(json_read(&doc, manifest, sizeof(manifest) - 1));
    CHECK(miner_signal_catalog_pin_parse(json_at(&doc, 0), json_at(&doc, 1),
        json_at(&doc, 2), json_at(&doc, 3),
        chain_params_get()->consensus.hashGenesisBlock.data, &pin).ok);
    json_free(&doc);
    char dir[512], ballots[600], path[720], digest[65], arg[96];
    CHECK(test_mkdtemp(dir, sizeof(dir), "boot_ballot"));
    CHECK(snprintf(ballots, sizeof(ballots), "%s/ballots", dir) > 0);
    CHECK(mkdir(ballots, 0700) == 0);
    zcl_hex_encode(pin.digest, 32, digest);
    CHECK(snprintf(path, sizeof(path), "%s/%s.json", ballots, digest) > 0);
    FILE *file = fopen(path, "wb");
    CHECK(file);
    CHECK(fwrite(manifest, 1, sizeof(manifest) - 1, file) == sizeof(manifest) - 1);
    CHECK(fclose(file) == 0);
    CHECK(snprintf(arg, sizeof(arg), "-testballotcatalog=%s", digest) > 0);
    const char *args[] = {"z23", arg};
    ParseParameters(2, args);
    ctx.datadir = dir;
    CHECK(boot_ballot_catalog_load(&ctx));
    const struct research_rules_binding *binding = research_rules_binding();
    CHECK(binding && binding->params == chain_params_get() &&
          binding->pin == &ctx.ballot_catalog_pin && ctx.ballot_catalog_pin_present);
    CHECK(chain_params_get()->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight == NETWORK_UPGRADE_ALWAYS_ACTIVE);
    CHECK(chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight == NETWORK_UPGRADE_ALWAYS_ACTIVE);
    CHECK(!research_rules_install(binding->params, binding->pin));
    chain_params_select(CHAIN_MAIN);
    CHECK(chain_params_get()->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight == main_ow);
    CHECK(chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight == main_sap);
    chain_params_select(CHAIN_REGTEST);
    CHECK(chain_params_get()->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight == reg_ow);
    CHECK(chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight == reg_sap);
    CHECK(unlink(path) == 0 && rmdir(ballots) == 0);
    test_cleanup_tmpdir(dir);
    ParseParameters(1, empty);
    chain_params_select(CHAIN_MAIN);
    return 0;
}
#else
int test_boot_ballot_catalog(void) { return 0; }
#endif
