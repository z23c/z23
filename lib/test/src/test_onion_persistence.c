/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for the persistent onion identity (-onion-persist / -onion-rotate).
 *
 * The identity lifecycle (seed mint/reuse/refuse-corrupt, hostname file,
 * rotation archive) is a pure file/crypto layer in tor_integration.c, so
 * every test here runs without a linked or running Tor: a fake datadir's
 * tor_data/onion_service directory plays the HiddenServiceDir, and two
 * onion_identity_ensure() calls play two boots. The install-into-dynhost
 * half only exists in real-Tor builds and is exercised on live boots. */

#include "test/test_core.h"
#include "net/tor_integration.h"
#include "config/boot.h"
#include "config/args.h"
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>

/* Recursively remove a directory tree (like rm -rf). */
static void remove_tree(const char *path)
{
    DIR *d = opendir(path);
    if (!d) { unlink(path); return; }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[1024];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        struct stat st;
        if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode))
            remove_tree(child);
        else
            unlink(child);
    }
    closedir(d);
    rmdir(path);
}

static bool file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* The pure derivation must match prop224 bit-for-bit: the pubkey comes
 * from RFC 8032 ed25519 (seed 00..1f → pk 03a107bf…5531b8, cross-checked
 * against an independent implementation) and the checksum/base32 recipe is
 * pinned against Tor's own hs_build_address test vector. */
static int test_onion_identity_vector(void)
{
    int failures = 0;
    printf("test_onion_identity_vector: ");

    uint8_t seed[32];
    for (int i = 0; i < 32; i++)
        seed[i] = (uint8_t)i;

    char addr[57];
    bool ok = onion_identity_address_from_seed(seed, addr, sizeof(addr));
    const char *expected =
        "aoqqpp7tzyil4hlq3umoos6atft6jvrqtosq2xy53sdgiesvgg4bqead";

    if (ok && strcmp(addr, expected) == 0 && strlen(addr) == 56) {
        printf("OK\n");
    } else {
        printf("FAIL (ok=%d addr='%s')\n", ok, addr);
        failures++;
    }

    return failures;
}

/* Two onion_identity_ensure() calls on one datadir = two boots: the first
 * mints, the second reuses — the address MUST be identical. */
static int test_onion_identity_stable_across_boots(void)
{
    int failures = 0;
    printf("test_onion_identity_stable_across_boots: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "onion_identity", "boot");

    uint8_t seed1[32], seed2[32];
    char addr1[64], addr2[64];
    bool created1 = false, created2 = true;

    bool ok1 = onion_identity_ensure(tmpdir, seed1, addr1, sizeof(addr1),
                                     &created1);
    /* Simulated restart: call again on the same datadir. */
    bool ok2 = onion_identity_ensure(tmpdir, seed2, addr2, sizeof(addr2),
                                     &created2);

    bool same = ok1 && ok2 && created1 && !created2 &&
                memcmp(seed1, seed2, 32) == 0 &&
                strcmp(addr1, addr2) == 0 && strlen(addr1) == 56;

    /* Hostname file carries the standard "<addr>.onion" content. */
    char hostname_path[1152];
    snprintf(hostname_path, sizeof(hostname_path),
             "%s/tor_data/onion_service/hostname", tmpdir);
    char expected_hn[80];
    snprintf(expected_hn, sizeof(expected_hn), "%s.onion", addr1);
    char hline[128] = "";
    FILE *f = fopen(hostname_path, "r");
    if (f) { if (!fgets(hline, sizeof(hline), f)) hline[0] = '\0'; fclose(f); }
    size_t hl = strlen(hline);
    while (hl > 0 && (hline[hl-1] == '\n' || hline[hl-1] == '\r'))
        hline[--hl] = '\0';
    bool hostname_ok = strcmp(hline, expected_hn) == 0;

    /* The seed is key material: mode 0600, never group/world-readable. */
    char seed_path[1152];
    snprintf(seed_path, sizeof(seed_path),
             "%s/tor_data/onion_service/identity_seed", tmpdir);
    struct stat st;
    bool mode_ok = stat(seed_path, &st) == 0 &&
                   (st.st_mode & 0777) == 0600;

    if (same && hostname_ok && mode_ok) {
        printf("OK\n");
    } else {
        printf("FAIL (same=%d hostname=%d mode=%d)\n",
               same, hostname_ok, mode_ok);
        failures++;
    }

    remove_tree(tmpdir);
    return failures;
}

/* A corrupt (short) seed must be a named refusal, never a silent remint —
 * silently reminting would change the shop's address without anyone
 * noticing. */
static int test_onion_identity_corrupt_seed_refused(void)
{
    int failures = 0;
    printf("test_onion_identity_corrupt_seed_refused: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "onion_identity", "corrupt");

    char dir[1152];
    snprintf(dir, sizeof(dir), "%s/tor_data/onion_service", tmpdir);
    char td[1152];
    snprintf(td, sizeof(td), "%s/tor_data", tmpdir);
    mkdir(td, 0700);
    mkdir(dir, 0700);

    char seed_path[1280];
    snprintf(seed_path, sizeof(seed_path), "%s/identity_seed", dir);
    FILE *f = fopen(seed_path, "w");
    if (!f) {
        printf("SKIP (cannot plant corrupt seed)\n");
        remove_tree(tmpdir);
        return 0;
    }
    fputs("ten bytes!", f);   /* 10 bytes, not 32 */
    fclose(f);

    uint8_t seed[32];
    char addr[64];
    bool refused = !onion_identity_ensure(tmpdir, seed, addr, sizeof(addr),
                                          NULL);
    /* The corrupt file is left in place for the operator to decide. */
    bool left = file_exists(seed_path);

    if (refused && left) {
        printf("OK\n");
    } else {
        printf("FAIL (refused=%d left=%d)\n", refused, left);
        failures++;
    }

    remove_tree(tmpdir);
    return failures;
}

/* -onion-rotate: archives the old identity under its address and the next
 * boot mints a DIFFERENT one. On an empty datadir rotation is a named
 * no-op (false), never an implicit mint. */
static int test_onion_identity_rotation(void)
{
    int failures = 0;
    printf("test_onion_identity_rotation: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "onion_identity", "rotate");

    uint8_t seed1[32], seed2[32];
    char addr1[64], addr2[64];
    bool ok1 = onion_identity_ensure(tmpdir, seed1, addr1, sizeof(addr1),
                                     NULL);

    char old[64];
    bool rotated = onion_identity_rotate(tmpdir, old, sizeof(old));

    /* Old identity archived under its own address; live seed gone. */
    char arch[1536];
    snprintf(arch, sizeof(arch),
             "%s/tor_data/onion_service/archive/identity_seed.%s",
             tmpdir, addr1);
    char live_seed[1280];
    snprintf(live_seed, sizeof(live_seed),
             "%s/tor_data/onion_service/identity_seed", tmpdir);
    bool archived = rotated && strcmp(old, addr1) == 0 &&
                    file_exists(arch) && !file_exists(live_seed);

    /* Next "boot" mints a fresh, different identity. */
    bool created2 = false;
    bool ok2 = onion_identity_ensure(tmpdir, seed2, addr2, sizeof(addr2),
                                     &created2);
    bool changed = ok1 && ok2 && created2 &&
                   memcmp(seed1, seed2, 32) != 0 &&
                   strcmp(addr1, addr2) != 0;

    if (archived && changed) {
        printf("OK\n");
    } else {
        printf("FAIL (archived=%d changed=%d)\n", archived, changed);
        failures++;
    }

    remove_tree(tmpdir);

    printf("test_onion_identity_rotation_empty_dir: ");
    char tmpdir2[512];
    test_make_tmpdir(tmpdir2, sizeof(tmpdir2), "onion_identity",
                     "rotate_empty");
    char old2[64];
    bool noop = !onion_identity_rotate(tmpdir2, old2, sizeof(old2));
    /* The named no-op must not mint anything implicitly. */
    char seed_path2[1280];
    snprintf(seed_path2, sizeof(seed_path2),
             "%s/tor_data/onion_service/identity_seed", tmpdir2);
    bool nothing_minted = !file_exists(seed_path2);
    if (noop && nothing_minted) {
        printf("OK\n");
    } else {
        printf("FAIL (noop=%d nothing_minted=%d)\n", noop, nothing_minted);
        failures++;
    }
    remove_tree(tmpdir2);

    return failures;
}

/* Default is ephemeral: persistence is OFF until configured, and
 * -onion-rotate without -onion-persist is ignored (prints its named
 * warning). State is reset afterwards — these globals are process-wide
 * and other groups share the test process. */
static int test_onion_ephemeral_default(void)
{
    int failures = 0;
    printf("test_onion_ephemeral_default: ");

    bool def = !tor_integration_persistence_enabled();
    struct tor_onion_port_map initial_map;
    tor_integration_port_map_snapshot(&initial_map);
    tor_integration_configure_identity(true, false);
    bool on = tor_integration_persistence_enabled();
    struct tor_onion_port_map configured_map;
    tor_integration_port_map_snapshot(&configured_map);
    tor_integration_configure_identity(false, true);   /* rotate alone */
    bool rotate_alone_ignored = !tor_integration_persistence_enabled();
    tor_integration_configure_identity(false, false);

    bool map_contract =
        initial_map.state == TOR_ONION_PORT_MAP_DISABLED &&
        initial_map.application_virtual_port == 80 &&
        initial_map.expected_route_count == 1 &&
        !initial_map.complete &&
        configured_map.persistent_identity &&
        configured_map.state == TOR_ONION_PORT_MAP_DISABLED &&
        strcmp(tor_onion_port_map_state_name(configured_map.state),
               "disabled") == 0;

    if (def && on && rotate_alone_ignored && map_contract) {
        printf("OK\n");
    } else {
        printf("FAIL (default=%d on=%d rotate_alone_ignored=%d map=%d)\n",
               def, on, rotate_alone_ignored, map_contract);
        failures++;
    }

    return failures;
}

/* The args parser must recognize both flags (an unrecognized one warns
 * every boot) and leave them off by default. */
static int test_onion_persist_args_parse(void)
{
    int failures = 0;
    printf("test_onion_persist_args_parse: ");

    struct app_context ctx = {0};
    bool show_metrics = false;
    char *argv[] = { "zclassic23", "-tor", "-onion-persist",
                     "-onion-rotate" };
    /* -1 is this function's "parsed OK" return (0 is help/version, 1 is
     * fatal) — see the return comment at the end of args.c. */
    int rc = args_parse_node_options(4, argv, &ctx, &show_metrics);
    bool parsed = rc == -1 && ctx.tor && ctx.onion_persist &&
                  ctx.onion_rotate;

    struct app_context ctx2 = {0};
    char *argv2[] = { "zclassic23" };
    int rc2 = args_parse_node_options(1, argv2, &ctx2, &show_metrics);
    bool defaults = rc2 == -1 && !ctx2.onion_persist && !ctx2.onion_rotate;

    if (parsed && defaults) {
        printf("OK\n");
    } else {
        printf("FAIL (parsed=%d defaults=%d)\n", parsed, defaults);
        failures++;
    }

    return failures;
}

static int test_stability_control_args_parse(void)
{
    int failures = 0;
    printf("test_stability_control_args_parse: ");

    struct app_context ctx = {0};
    bool show_metrics = false;
    char *valid[] = { "zclassic23", "-utxomirror=off",
                      "-bodyhistorybackfill=normal", "-legacyoracle=off" };
    int rc = args_parse_node_options(4, valid, &ctx, &show_metrics);
    bool parsed = rc == -1 &&
        getenv("ZCL_UTXO_MIRROR_MODE") &&
        strcmp(getenv("ZCL_UTXO_MIRROR_MODE"), "off") == 0 &&
        getenv("ZCL_BODY_HISTORY_BACKFILL_MODE") &&
        strcmp(getenv("ZCL_BODY_HISTORY_BACKFILL_MODE"), "normal") == 0 &&
        getenv("ZCL_LEGACY_ORACLE_MODE") &&
        strcmp(getenv("ZCL_LEGACY_ORACLE_MODE"), "off") == 0;

    struct app_context bad_ctx = {0};
    char *invalid[] = { "zclassic23", "-utxomirror=rebuild" };
    bool invalid_refused =
        args_parse_node_options(2, invalid, &bad_ctx, &show_metrics) == 1;

    unsetenv("ZCL_UTXO_MIRROR_MODE");
    unsetenv("ZCL_BODY_HISTORY_BACKFILL_MODE");
    unsetenv("ZCL_LEGACY_ORACLE_MODE");

    if (parsed && invalid_refused) {
        printf("OK\n");
    } else {
        printf("FAIL (parsed=%d invalid_refused=%d)\n",
               parsed, invalid_refused);
        failures++;
    }
    return failures;
}

static int test_auto_local_peer_refuses_self_endpoint(void)
{
    int failures = 0;
    printf("test_auto_local_peer_refuses_self_endpoint: ");
    bool ok =
        !args_should_auto_add_local_peer(false, 8033, 8033, false) &&
        args_should_auto_add_local_peer(false, 8033, 8034, false) &&
        !args_should_auto_add_local_peer(true, 8033, 8034, false) &&
        !args_should_auto_add_local_peer(false, 8033, 8034, true) &&
        !args_should_auto_add_local_peer(false, 0, 8034, false) &&
        !args_should_auto_add_local_peer(false, 8033, 0, false);
    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }
    return failures;
}

int test_onion_persistence(void)
{
    int failures = 0;
    printf("\n=== Persistent Onion Identity Tests ===\n");

    failures += test_onion_identity_vector();
    failures += test_onion_identity_stable_across_boots();
    failures += test_onion_identity_corrupt_seed_refused();
    failures += test_onion_identity_rotation();
    failures += test_onion_ephemeral_default();
    failures += test_onion_persist_args_parse();
    failures += test_stability_control_args_parse();
    failures += test_auto_local_peer_refuses_self_endpoint();

    printf("Persistent onion identity: %d failures\n", failures);
    return failures;
}
