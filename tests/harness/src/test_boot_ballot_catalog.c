/* purpose: Verify explicit research boot consent and process-lifetime binding. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "base/hex.h"
#include "chain/chainparams.h"
#include "config/boot.h"
#include "config/boot_ballot_catalog.h"
#include "consensus/params.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "services/research_rules.h"
#include "test/test_core.h"
#include "util/util.h"
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "boot ballot catalog line %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static struct app_context ctx;
static const char manifest[] =
    "[\"1111111111111111111111111111111111111111111111111111111111111111\",100,20,"
    "[[\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",122]]]";

struct snapshot_item {
    char path[1024];
    off_t size;
    unsigned char hash[32];
};
struct snapshot { struct snapshot_item items[32]; size_t count; };

static bool snapshot_file(const char *path, struct snapshot_item *item)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    unsigned char buf[1024]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f))) sha3_256_write(&hash, buf, n);
    bool ok = !ferror(f);
    if (fclose(f)) ok = false;
    sha3_256_finalize(&hash, item->hash);
    return ok;
}

static bool snapshot_tree(const char *root, const char *rel, struct snapshot *out)
{
    char path[1024];
    if (snprintf(path, sizeof(path), "%s%s", root, rel) >= (int)sizeof(path)) return false;
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool ok = true;
    struct dirent *entry;
    while (ok && (entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char child[1024], full[2048];
        if (snprintf(child, sizeof(child), "%s/%s", rel, entry->d_name) >= (int)sizeof(child) ||
            snprintf(full, sizeof(full), "%s%s", root, child) >= (int)sizeof(full)) { ok = false; break; }
        struct stat st;
        if (lstat(full, &st) || out->count == 32) { ok = false; break; }
        struct snapshot_item *item = &out->items[out->count++];
        memcpy(item->path, child, strlen(child) + 1);
        item->size = st.st_size;
        if (S_ISDIR(st.st_mode)) {
            ok = snapshot_tree(root, child, out);
        } else if (S_ISREG(st.st_mode)) {
            ok = snapshot_file(full, item);
        } else ok = false;
    }
    if (closedir(dir)) ok = false;
    return ok;
}

static bool snapshot_equal(const struct snapshot *a, const struct snapshot *b)
{
    if (a->count != b->count) return false;
    for (size_t i = 0; i < a->count; ++i) {
        bool found = false;
        for (size_t j = 0; j < b->count; ++j)
            if (!strcmp(a->items[i].path, b->items[j].path) &&
                a->items[i].size == b->items[j].size &&
                !memcmp(a->items[i].hash, b->items[j].hash, 32)) found = true;
        if (!found) return false;
    }
    return true;
}

static bool refusal_case(const char *dir, const char *arg, const char *cause)
{
    struct snapshot before = {0}, after = {0};
    if (!snapshot_tree(dir, "", &before)) return false;
    FILE *capture = tmpfile();
    if (!capture) return false;
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    if (saved < 0 || dup2(fileno(capture), STDERR_FILENO) < 0) return false;
    const char *args[] = {"z23", arg};
    ParseParameters(2, args);
    const struct research_rules_binding *binding = research_rules_binding();
    bool refused = !boot_ballot_catalog_load(&ctx);
    fflush(stderr);
    bool ok = dup2(saved, STDERR_FILENO) >= 0 && close(saved) == 0;
    rewind(capture);
    char message[1024] = {0};
    (void)fread(message, 1, sizeof(message) - 1, capture);
    if (fclose(capture)) ok = false;
    return ok && refused && strstr(message, cause) && research_rules_binding() == binding &&
        !ctx.ballot_catalog_pin_present && snapshot_tree(dir, "", &after) &&
        snapshot_equal(&before, &after);
}

static bool prologue_refusal(const char *dir)
{
    pid_t child = fork();
    if (child == 0) {
        const char *args[] = {"z23"};
        ParseParameters(1, args);
        struct app_context boot = {0};
        boot.datadir = dir;
        boot.testnet_profile = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
        bool refused = !app_init(&boot);
        const struct chain_params *selected = chain_params_get();
        _exit(refused &&
              selected->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight != NETWORK_UPGRADE_ALWAYS_ACTIVE &&
              selected->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight != NETWORK_UPGRADE_ALWAYS_ACTIVE
                  ? 0 : 1);
    }
    int status;
    struct snapshot after = {0};
    return child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0 && snapshot_tree(dir, "", &after) && after.count == 0;
}

static bool binary_fresh(void)
{
    struct stat binary, source;
    const char *files[] = {"engine/entry/main.c", "engine/composition/src/boot.c",
        "engine/composition/src/boot_ballot_catalog.c"};
    if (stat("build/bin/z23", &binary)) return false;
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i)
        if (stat(files[i], &source) || source.st_mtime > binary.st_mtime) return false;
    return true;
}

static void binary_child(const char *home, const char *arg, const char *pin, FILE *capture)
{
    alarm(10);
    int nullfd = open("/dev/null", O_WRONLY);
    if (nullfd < 0 || dup2(nullfd, STDOUT_FILENO) < 0 ||
        dup2(fileno(capture), STDERR_FILENO) < 0 || setenv("HOME", home, 1))
        _exit(127);
    close(nullfd);
    execl("build/bin/z23", "z23", arg, "-testnet-profile=ironwood", pin, (char *)NULL);
    _exit(127);
}

static bool binary_refuse(const char *home, const char *parent, const char *pin,
                          int *rc, char *out, size_t cap)
{
    char arg[1024];
    if (snprintf(arg, sizeof(arg), "-datadir=%s", parent) >= (int)sizeof(arg)) return false;
    FILE *capture = tmpfile();
    if (!capture) return false;
    pid_t child = fork();
    if (child == 0) binary_child(home, arg, pin, capture);
    int status = 0;
    bool ok = child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status);
    *rc = ok ? WEXITSTATUS(status) : -1;
    rewind(capture);
    size_t n = fread(out, 1, cap - 1, capture);
    out[n] = '\0';
    if (ferror(capture)) ok = false;
    if (fclose(capture)) ok = false;
    return ok && *rc != 0 && *rc != 127 &&
        strstr(out, "the research profile requires an explicitly pinned catalog") &&
        (!pin || strstr(out, "must be exactly 64 lowercase hexadecimal characters"));
}

static bool write_fixture_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t len = strlen(text);
    bool ok = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static bool binary_marked_fixture(const char *dir, const char *marker, const char *sentinel,
                                  struct snapshot *before)
{
    return mkdir(dir, 0700) == 0 &&
        write_fixture_file(marker, "z23-research-profile:ironwood:v1\n") &&
        write_fixture_file(sentinel, "untouched\n") && chmod(dir, 0755) == 0 &&
        snapshot_tree(dir, "", before);
}

static bool binary_unchanged(const char *dir, bool existing, const struct snapshot *before)
{
    struct stat st;
    struct snapshot after = {0};
    return existing ? stat(dir, &st) == 0 && (st.st_mode & 0777) == 0755 &&
        snapshot_tree(dir, "", &after) && snapshot_equal(before, &after) :
        lstat(dir, &st) != 0 && errno == ENOENT;
}

static void binary_consent_report(bool existing, const char *pin, bool ready,
                                  bool refused, bool unchanged, int rc, const char *output)
{
    if (refused && unchanged)
        printf("binary consent %s %s: rc=%d stderr=%s", existing ? "marked" : "absent",
               pin ? pin : "(no pin)", rc, output);
    if (!refused || !unchanged)
        fprintf(stderr, "binary consent %s %s: refused=%d rc=%d unchanged=%d output=%s\n",
                existing ? "marked" : "absent", pin ? pin : "(no pin)", refused, rc,
                unchanged, ready ? output : "(setup failed)");
}

static int binary_consent_case(bool existing, const char *pin)
{
    char home[512], parent[600], dir[700], marker[800], sentinel[800], output[4096] = {0};
    struct snapshot before = {0};
    int rc = -1;
    if (!test_mkdtemp(home, sizeof(home), "ballot_binary")) return 1;
    snprintf(parent, sizeof(parent), "%s/parent", home);
    snprintf(dir, sizeof(dir), "%s/ironwood-research", parent);
    snprintf(marker, sizeof(marker), "%s/.z23-research-profile", dir);
    snprintf(sentinel, sizeof(sentinel), "%s/sentinel", dir);
    bool ready = mkdir(parent, 0700) == 0;
    if (ready && existing)
        ready = binary_marked_fixture(dir, marker, sentinel, &before);
    bool refused = ready && binary_refuse(home, parent, pin, &rc, output, sizeof(output));
    bool unchanged = binary_unchanged(dir, existing, &before);
    binary_consent_report(existing, pin, ready, refused, unchanged, rc, output);
    (void)test_rm_rf_recursive(home);
    return refused && unchanged ? 0 : 1;
}

int test_boot_ballot_catalog(void)
{
    CHECK(binary_fresh());
    const char *pins[] = {NULL, "-notestballotcatalog", "-testballotcatalog=",
        "-testballotcatalog", "-testballotcatalog=123",
        "-testballotcatalog=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"};
    int binary_failures = 0;
    for (size_t i = 0; i < sizeof(pins) / sizeof(pins[0]); ++i)
        binary_failures += binary_consent_case(false, pins[i]) + binary_consent_case(true, pins[i]);
    CHECK(binary_failures == 0);
    const char *valid[] = {"z23", "-testballotcatalog=0000000000000000000000000000000000000000000000000000000000000000"};
    ParseParameters(2, valid);
    CHECK(boot_ballot_catalog_consent_present());
    const char *empty[] = {"z23"};
    ParseParameters(1, empty);
    chain_params_select(CHAIN_MAIN);
    int main_ow = chain_params_get()->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight;
    int main_sap = chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight;
    chain_params_select(CHAIN_REGTEST);
    int reg_ow = chain_params_get()->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight;
    int reg_sap = chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight;
    CHECK(chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD));
    /* Shielded upgrades activate only when a verified catalog binds. */
    int research_ow = chain_params_get()->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight;
    int research_sap = chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight;
    CHECK(research_ow != NETWORK_UPGRADE_ALWAYS_ACTIVE && research_sap != NETWORK_UPGRADE_ALWAYS_ACTIVE);
    CHECK(!boot_ballot_catalog_load(&ctx) && !research_rules_binding());
    CHECK(chain_params_get()->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight == research_ow &&
          chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight == research_sap);
    struct miner_signal_catalog_pin wrong = {0};
    CHECK(!research_rules_install(chain_params_get(), &wrong) && !research_rules_binding());
    CHECK(chain_params_get()->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight == research_ow &&
          chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight == research_sap);

    struct json_value doc = {0};
    struct miner_signal_catalog_pin pin = {0};
    CHECK(json_read(&doc, manifest, sizeof(manifest) - 1));
    CHECK(miner_signal_catalog_pin_parse(json_at(&doc, 0), json_at(&doc, 1),
        json_at(&doc, 2), json_at(&doc, 3),
        chain_params_get()->consensus.hashGenesisBlock.data, &pin).ok);
    json_free(&doc);
    char dir[512], ballots[600], path[720], digest[65], arg[96];
    CHECK(test_mkdtemp(dir, sizeof(dir), "boot_ballot"));
    CHECK(prologue_refusal(dir));
    CHECK(snprintf(ballots, sizeof(ballots), "%s/ballots", dir) > 0);
    CHECK(mkdir(ballots, 0700) == 0);
    ctx.datadir = dir;
    struct miner_signal_catalog_pin foreign = {0};
    chain_params_select(CHAIN_REGTEST);
    CHECK(json_read(&doc, manifest, sizeof(manifest) - 1));
    CHECK(miner_signal_catalog_pin_parse(json_at(&doc, 0), json_at(&doc, 1),
        json_at(&doc, 2), json_at(&doc, 3),
        chain_params_get()->consensus.hashGenesisBlock.data, &foreign).ok);
    json_free(&doc);
    CHECK(chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD));
    zcl_hex_encode(foreign.digest, 32, digest);
    CHECK(snprintf(path, sizeof(path), "%s/%s.json", ballots, digest) > 0);
    FILE *file = fopen(path, "wb");
    CHECK(file && fwrite(manifest, 1, sizeof(manifest) - 1, file) == sizeof(manifest) - 1);
    CHECK(fclose(file) == 0);
    CHECK(snprintf(arg, sizeof(arg), "-testballotcatalog=%s", digest) > 0);
    CHECK(refusal_case(dir, arg, "digest mismatch"));
    ctx.testnet = true;
    CHECK(refusal_case(dir, arg, "research profile cannot be combined"));
    ctx.testnet = false;
    CHECK(unlink(path) == 0);
    zcl_hex_encode(pin.digest, 32, digest);
    CHECK(snprintf(path, sizeof(path), "%s/%s.json", ballots, digest) > 0);
    file = fopen(path, "wb");
    CHECK(file && fwrite("{", 1, 1, file) == 1 && fclose(file) == 0);
    CHECK(snprintf(arg, sizeof(arg), "-testballotcatalog=%s", digest) > 0);
    CHECK(refusal_case(dir, arg, "Invalid ballot catalog manifest JSON"));
    file = fopen(path, "wb");
    CHECK(file);
    CHECK(fwrite(manifest, 1, sizeof(manifest) - 1, file) == sizeof(manifest) - 1);
    CHECK(fclose(file) == 0);
    CHECK(snprintf(arg, sizeof(arg), "-testballotcatalog=%s", digest) > 0);
    const char *args[] = {"z23", arg};
    ParseParameters(2, args);
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
