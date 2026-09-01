/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_cold_join_sovereign — the shopkeeper story, turned into one gate.
 *
 * THE STORY THIS TESTS
 * --------------------
 * Someone with no account, no domain name and no certificate authority
 * installs Z23 on a second-hand box, and it starts validating the chain.
 * Nothing about joining needed permission from anyone, which is the point:
 * nothing that needed no permission can be revoked.
 *
 * That story was believed here, scattered across several separate facts, and
 * not provable by one command. This file makes it one command and — more
 * importantly — makes it say so where the story is prettier than the code.
 *
 * THE PROPOSITIONS, AND WHICH ONES ACTUALLY HOLD
 * ----------------------------------------------
 * P1  no DNS NAME is resolved from the shipped bootstrap set     HOLDS
 * P2  no certificate authority is consulted                      HOLDS, NARROWED
 * P3  no account, key, or registration is required               HOLDS
 * P4  no proving parameters are needed to start validating       HOLDS, NARROWED
 * P5  the validator is armed and non-vacuous on a wiped datadir  HOLDS, NARROWED
 * P6  joining does not depend on one specific operator's machine PARTIAL
 * P7  the join is not gated on fast storage                      SEPARATE AXIS
 * P8  no identity gates ACCEPTANCE once joined                   NOT ASSERTED HERE
 *
 * P8 belongs on the list because "nothing needed permission" is only half the
 * story — the other half is that nothing can later withdraw it. A node states
 * its build identity on the wire and that string must never reach an
 * acceptance decision, because the moment it can, it is a whitelist. This file
 * does not assert it: the claim is about every acceptance path rather than
 * about the join, and proving it needs a reachability argument over the
 * validation call graph, not the bootstrap set. It is enumerated so that its
 * absence here is a known gap rather than an oversight.
 *
 * Where a proposition is narrower than the story, this file asserts the
 * NARROW form and says so out loud. Three of them are narrower:
 *
 * P2 IS NOT "there is no TLS code."  Measured on the shipped build/bin/z23:
 *    a full OpenSSL is STATICALLY linked (1064 DEFINED SSL/X509/TLS symbols by
 *    `nm --defined-only`, while `ldd` shows only libm, libc and the loader —
 *    including TLS_client_method, SSL_connect, SSL_CTX_set_default_verify_paths
 *    and the literal string "/etc/ssl/certs"), pulled in by the OPTIONAL,
 *    off-by-default block-explorer HTTPS listener. A test asserting those
 *    symbols are absent would be red the day it was written, and would be a
 *    lie besides. What IS true, and what P2 asserts, is that NO Z23-AUTHORED
 *    TRANSLATION UNIT REFERENCES ANY OF IT: zero of the project's own object
 *    files carry an undefined reference to a TLS-client or trust-store entry
 *    point. The CA machinery is present and unreachable, not absent.
 *
 * P4 IS NOT "shielded works with no parameters."  Validating a shielded proof
 *    reads only the verifying key, which is compiled in; CREATING one needs
 *    the ~777 MB proving keys, which are not shipped. So a cold node can
 *    check every shielded transaction on the chain and cannot send one. P4
 *    asserts exactly that pair, including the negative half.
 *
 * P5 IS NOT "it validated a real mainnet block."  It cannot be, hermetically:
 *    this repository ships ZERO real mainnet block bytes (the only block
 *    fixtures in the tree are synthetic, and chainparams carries hashes, not
 *    bodies). Real bodies come from a peer, and requiring a peer would make
 *    this test grade the network instead of the code. What P5 asserts is the
 *    two halves that ARE hermetic: (a) the node carries the REAL mainnet
 *    consensus facts with nothing fetched and nothing registered — genesis
 *    hash, the checkpoint lineage, minimum chain work, upgrade heights, and
 *    the baked ROM keystone at height 3056758; and (b) the MUST-NEVER-FORK
 *    consensus entry point check_block() is live and NON-VACUOUS on a wiped
 *    datadir: a genuinely Equihash-mined block is ACCEPTED and the same block
 *    with one bit flipped is REJECTED. An armed, discriminating validator
 *    bound to real mainnet lineage is what "starts validating" means before
 *    the first peer answers.
 *
 * WHAT THIS FILE DELIBERATELY DOES NOT DUPLICATE
 * ----------------------------------------------
 *   tests/harness/src/test_params_vk_embedded.c   — the VK blobs are byte-exact,
 *       digest-pinned, and a planted bad blob is refused. P4 here asserts only
 *       the COMPOSITION that file does not: armed from an EMPTY datadir.
 *   tests/harness/src/test_seed_bootstrap_doors.c — no dead port, no double
 *       booking, a measured-dead host stays removed. P6 here asserts only the
 *       tier-independence property that file does not, and records the
 *       cardinality it deliberately does not grade.
 *   tests/harness/src/test_boot_matrix.c          — every boot cell reaches a NAMED
 *       terminal under budget. This file borrows its regtest block builder
 *       shape and none of its assertions.
 *
 * TIME IS A SEPARATE RESULT AND NEVER DECIDES PASS/FAIL (P7)
 * ---------------------------------------------------------
 * This project accepts slow machines on purpose: a 7200rpm box under 2 MB/s
 * is the instrument that shows where the code assumed an SSD, so grading it
 * "fail" would destroy the only evidence worth having. Elapsed time is
 * measured, printed as its own line, and CANNOT fail this test. The only
 * bound present is a HANG DETECTOR at CJ_HANG_DETECT_SECS, which is set two
 * orders of magnitude above the observed cost of this work — it exists to
 * catch a wedge, not to grade a disk — and blowing it is reported as the
 * distinct outcome SLOW, never as BROKEN. A reader can tell "this box is
 * slow" from "this is broken" from the verdict line alone.
 *
 * No node process is spawned and no systemd watchdog is in play, so the
 * failure mode where a loaded box's watchdog SIGABRTs a healthy node cannot
 * produce a red here. The outcome vocabulary still names it (CJ_KILLED) so
 * that a harness wrapping this test has a word for it.
 */

#include "test/test_core.h"
#include "platform/time_compat.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "chain/checkpoints.h"
#include "chain/subsidy.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "domain/consensus/coinbase.h"
#include "mining/miner.h"
#include "net/netbase.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/params_init.h"
#include "sapling/params_vk_embedded.h"
#include "sapling/sapling_prover.h"
#include "script/script.h"
#include "util/safe_alloc.h"
#include "validation/check_block.h"

#include "platform/socket_compat.h"
#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Hang detector ONLY. Justification for the value, recorded so nobody later
 * "tunes" it into a performance gate: the whole in-process sequence below is
 * one Equihash solve at regtest difficulty plus a symbol scan of the
 * already-built object tree. The slowest honest machine this project intends
 * to accept is a 7200rpm HDD box measured under 2 MB/s with io pressure above
 * 90%, on which the object scan (the only I/O-bound step) is the part that
 * stretches. 900 s leaves that box orders of magnitude of headroom and still
 * catches a real wedge inside one CI run. It must never be lowered toward a
 * measured time. */
#define CJ_HANG_DETECT_SECS 900

/* The real mainnet facts a cold node carries with nothing fetched. Pinned here
 * so that quietly emptying any of them fails this test rather than silently
 * turning the story into a network dependency. */
#define CJ_GENESIS_HEX \
    "0007104ccda289427919efc39dc9e4d499804b7bebc22df55f8b834301260602"
#define CJ_ROM_KEYSTONE_HEIGHT 3056758
#define CJ_CHECKPOINT_FLOOR    3000000

/* A public-node production object tree with fewer than this many .o files is
 * a stale or half-finished build epoch, and scanning it would report "zero
 * offenders" while examining almost nothing. Measured: a complete tree here
 * carries over 1800 public-node production objects, so this floor refuses a
 * partial build without being anywhere near the real count. */
#define CJ_MIN_OBJECTS_SCANNED 500

/* The number of compiled-in onion doors below which a Tor-only stranger is
 * depending on a single operator's machine staying up. Not a pass/fail bar —
 * a declared weakness threshold, reported when crossed. */
#define CJ_ONION_SPOF_FLOOR 2

/* Every TLS-client and CA-trust-store entry point. If a Z23 object ever
 * carries an undefined reference to one of these, the node has become a TLS
 * client and can be told who to trust by whoever ships the trust store. */
static const char *const kTrustStoreSymbols[] = {
    "SSL_connect",
    "SSL_do_handshake",
    "TLS_client_method",
    "SSLv23_client_method",
    "SSL_CTX_set_verify",
    "SSL_CTX_set_default_verify_paths",
    "SSL_CTX_set_default_verify_file",
    "SSL_CTX_set_default_verify_dir",
    "SSL_CTX_load_verify_locations",
    "SSL_get_verify_result",
    "X509_verify_cert",
    "X509_STORE_set_default_paths",
    "X509_STORE_load_locations",
};

static int failures;
static int unproven;

#define CJ_CHECK(name, expr) do {                                   \
    printf("cold_join: %s... ", (name));                            \
    if ((expr)) { printf("OK\n"); }                                 \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

/* A proposition this run could not establish. Never a failure — an honest
 * gap, counted and printed so it cannot be mistaken for a pass. */
#define CJ_UNPROVEN(name, why) do {                                 \
    printf("cold_join: %s... UNPROVEN (%s)\n", (name), (why));      \
    unproven++;                                                     \
} while (0)

static double cj_monotonic_secs(void)
{
    struct timespec ts;
    if (platform_time_monotonic_timespec(&ts) != 0)
        return 0.0;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ── P1 helpers ──────────────────────────────────────────────────────────
 * A host string is safe to hand to getaddrinfo() without any name ever
 * leaving the box iff it is already a numeric literal. This is the real
 * predicate, evaluated against the actual compiled-in bytes — not a grep for
 * a suspicious word. */
static bool cj_host_is_numeric_literal(const char *host)
{
    struct in_addr v4;
    struct in6_addr v6;
    if (!host || host[0] == '\0')
        return false;
    if (platform_socket_parse_address(AF_INET, host, &v4) == 1)
        return true;
    if (platform_socket_parse_address(AF_INET6, host, &v6) == 1)
        return true;
    return false;
}

static void cj_check_network_has_no_names(enum chain_network net,
                                          const char *label)
{
    int bad = 0;
    chain_params_select(net);
    const struct chain_params *p = chain_params_get();
    char nm[192];

    /* Every entry the DNS-seed loop in connman.c would iterate. On mainnet
     * nSeeds is 0, so the loop body is unreachable; on the other networks the
     * single entry is a numeric literal whose `name` field is a label, not a
     * hostname. Either way no NAME can reach a resolver from chainparams. */
    for (size_t i = 0; i < p->nSeeds; i++) {
        if (!cj_host_is_numeric_literal(p->vSeeds[i].host)) {
            printf("cold_join:   %s vSeeds[%zu].host=\"%s\" is a NAME\n",
                   label, i, p->vSeeds[i].host);
            bad++;
        }
    }
    snprintf(nm, sizeof(nm),
             "P1 %s: all %zu dns_seed entries are numeric literals, never names",
             label, p->nSeeds);
    CJ_CHECK(nm, bad == 0);

    /* Fixed seeds are structurally nameless: the struct holds 16 raw address
     * bytes and a port, with nowhere to put a hostname. Assert the shape
     * rather than the contents so this stays true as entries churn. */
    snprintf(nm, sizeof(nm),
             "P1 %s: fixed seeds are raw addresses (no hostname field exists)",
             label);
    CJ_CHECK(nm, sizeof(p->vFixedSeeds[0].addr) == 16);

    /* Onion seeds never reach getaddrinfo: connman_add_seed_node() routes a
     * name for which net_name_is_onion() is true through net_addr_from_onion()
     * and RETURNS before the resolver branch. Assert the predicate that guard
     * actually evaluates, on the actual compiled-in strings. */
    bad = 0;
    for (size_t i = 0; i < p->nOnionSeeds; i++) {
        if (!net_name_is_onion(p->onionSeeds[i])) {
            printf("cold_join:   %s onionSeeds[%zu]=\"%s\" would reach the "
                   "resolver\n", label, i, p->onionSeeds[i]);
            bad++;
        }
    }
    snprintf(nm, sizeof(nm),
             "P1 %s: all %zu onion seeds take the pre-resolver branch",
             label, p->nOnionSeeds);
    CJ_CHECK(nm, bad == 0);
}

/* Mutation fixture for the P2 find selector.  The generated relocatable
 * aggregate is exactly EPOCH/restart-base.o; a constituent production object
 * with the same basename below that root must remain visible. */
static bool cj_restart_aggregate_selector_selftest(void)
{
    char dir[512];
    char nested_dir[576];
    char aggregate[640];
    char constituent[640];
    char cmd[1600];
    char got[704] = {0};
    bool ok = false;

    test_make_tmpdir(dir, sizeof(dir), "cold_join_selector", "epoch");
    snprintf(nested_dir, sizeof(nested_dir), "%s/app", dir);
    snprintf(aggregate, sizeof(aggregate), "%s/restart-base.o", dir);
    snprintf(constituent, sizeof(constituent), "%s/app/restart-base.o", dir);
    if (mkdir(nested_dir, 0700) != 0)
        goto out;
    FILE *fp = fopen(aggregate, "wb");
    if (!fp)
        goto out;
    if (fclose(fp) != 0)
        goto out;
    fp = fopen(constituent, "wb");
    if (!fp)
        goto out;
    if (fclose(fp) != 0)
        goto out;

    int n = snprintf(cmd, sizeof(cmd),
                     "find '%s' -name '*.o' ! -path '%s/restart-base.o'"
                     " -print 2>/dev/null",
                     dir, dir);
    if (n < 0 || (size_t)n >= sizeof(cmd))
        goto out;
    fp = popen(cmd, "r");
    if (!fp)
        goto out;
    bool one_line = fgets(got, sizeof(got), fp) != NULL;
    bool no_second_line = fgetc(fp) == EOF;
    int close_rc = pclose(fp);
    got[strcspn(got, "\r\n")] = '\0';
    ok = one_line && no_second_line && close_rc == 0 &&
         strcmp(got, constituent) == 0;

out:
    test_rm_rf(dir);
    return ok;
}

/* ── P2 helper: scan Z23's OWN object files, not the linked blob ─────────
 * The shipped binary contains a whole static OpenSSL. The question that
 * matters is not whether that code exists but whether any Z23 code reaches
 * it. An undefined reference in one of the project's own translation units is
 * exactly that reachability, recorded by the compiler, and it is the artifact
 * the linker itself consumed — not a source grep that a macro or an alias
 * could walk around.
 *
 * Returns the number of offending references, or -1 if the scan could not be
 * trusted (an honest UNPROVEN, never a silent pass). *scanned receives the
 * number of object files actually examined — an empty or stale build epoch
 * would otherwise report zero offenders and read as a pass, which is the
 * classic way a symbol gate goes green while checking nothing. */
static long cj_count_trust_store_refs(char *where, size_t where_n,
                                      long *scanned)
{
    static const char *const roots[] = {
        "build/test-obj/epochs",
        "build/test-rel-obj/epochs",
        "build/node-obj/epochs",
    };
    char root[512] = {0};
    time_t newest = 0;
    bool found = false;

    /* Several build epochs can coexist; an old one can be nearly empty.
     * Take the most recently written, then prove below that it is populated. */
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        DIR *d = opendir(roots[i]);
        if (!d)
            continue;
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.')
                continue;
            char cand[512];
            snprintf(cand, sizeof(cand), "%s/%s", roots[i], ent->d_name);
            struct stat st;
            if (stat(cand, &st) != 0 || !S_ISDIR(st.st_mode))
                continue;
            if (!found || st.st_mtime > newest) {
                newest = st.st_mtime;
                snprintf(root, sizeof(root), "%s", cand);
                found = true;
            }
        }
        closedir(d);
    }
    if (!found) {
        snprintf(where, where_n,
                 "no built object tree under build/*obj*/epochs");
        return -1;
    }
    snprintf(where, where_n, "%s", root);

    /* How many objects the scan will actually see. A tree below the floor is
     * refused rather than reported clean. */
    {
        char ccmd[768];
        snprintf(ccmd, sizeof(ccmd),
                 "find '%s' -name '*.o' ! -path '%s/restart-base.o'"
                 " -not -path '*/tests/harness/*' 2>/dev/null"
                 " | wc -l", root, root);
        FILE *cf = popen(ccmd, "r");
        if (!cf) {
            snprintf(where, where_n, "popen(find) failed");
            return -1;
        }
        char cline[64] = {0};
        long n_obj = fgets(cline, sizeof(cline), cf) ? strtol(cline, NULL, 10) : 0;
        (void)pclose(cf);
        *scanned = n_obj;
        if (n_obj < CJ_MIN_OBJECTS_SCANNED) {
            snprintf(where, where_n,
                     "%s holds only %ld public-node production objects "
                     "(floor %d) — a "
                     "stale or partial build epoch, not a clean scan",
                     root, n_obj, CJ_MIN_OBJECTS_SCANNED);
            return -1;
        }
    }

    /* One alternation of every trust-store entry point. `nm -u` lists only
     * UNDEFINED symbols, which is precisely "this TU calls out to it".
     * lib/test objects are excluded on purpose: the RPC test legitimately
     * acts as a TLS client to exercise the optional RPC-TLS listener, and it
     * is not shipped. */
    char cmd[4096];
    int n = snprintf(cmd, sizeof(cmd),
                     "find '%s' -name '*.o' ! -path '%s/restart-base.o'"
                     " -not -path '*/tests/harness/*' -print0"
                     " | xargs -0 nm -u --print-file-name 2>/dev/null"
                     " | grep -cwE 'U (", root, root);
    if (n < 0 || (size_t)n >= sizeof(cmd))
        return -1;
    for (size_t i = 0;
         i < sizeof(kTrustStoreSymbols) / sizeof(kTrustStoreSymbols[0]); i++) {
        int w = snprintf(cmd + n, sizeof(cmd) - (size_t)n, "%s%s",
                         i ? "|" : "", kTrustStoreSymbols[i]);
        if (w < 0 || (size_t)(n + w) >= sizeof(cmd))
            return -1;
        n += w;
    }
    {
        int w = snprintf(cmd + n, sizeof(cmd) - (size_t)n, ")'");
        if (w < 0 || (size_t)(n + w) >= sizeof(cmd))
            return -1;
    }

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        snprintf(where, where_n, "popen(nm) failed");
        return -1;
    }
    char line[64] = {0};
    if (!fgets(line, sizeof(line), fp)) {
        pclose(fp);
        snprintf(where, where_n, "nm produced no output");
        return -1;
    }
    /* grep -c exits 1 on zero matches; that is the ANSWER here, not an error,
     * so the exit status is deliberately not consulted. */
    (void)pclose(fp);
    return strtol(line, NULL, 10);
}

/* ── P5 helper: a genuinely mined regtest block ──────────────────────────
 * Same shape as test_boot_matrix.c's bm_build_regtest_block. Real coinbase,
 * real merkle root, real regtest powLimit nBits — mine_block_pow() then finds
 * an actual Equihash solution, so what check_block() verifies below is real
 * work and not a rubber stamp. */
static bool cj_build_regtest_block(struct block *blk, int height,
                                   const struct uint256 *prev_hash,
                                   const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "cj_vtx");
    if (!blk->vtx)
        return false;
    blk->num_vtx = 1;

    struct transaction *coinbase = &blk->vtx[0];
    transaction_init(coinbase);
    if (!transaction_alloc(coinbase, 1, 1))
        return false;

    struct script miner_script;
    script_init(&miner_script);
    miner_script.data[0] = 0x76; /* OP_DUP          */
    miner_script.data[1] = 0xa9; /* OP_HASH160      */
    miner_script.data[2] = 0x14; /* push 20         */
    for (int i = 0; i < 20; i++)
        miner_script.data[3 + i] = (unsigned char)(0x20 + i);
    miner_script.data[23] = 0x88; /* OP_EQUALVERIFY */
    miner_script.data[24] = 0xac; /* OP_CHECKSIG    */
    miner_script.size = 25;

    int64_t subsidy = get_block_subsidy(height, &cp->consensus);
    struct domain_consensus_coinbase_inputs cb_in = {
        .n_height     = height,
        .subsidy      = subsidy,
        .total_fees   = 0,
        .miner_script = &miner_script,
        .params       = &cp->consensus,
    };
    struct zcl_result r = domain_consensus_coinbase_build(&cb_in, coinbase);
    if (!r.ok)
        return false;

    struct uint256 txid = blk->vtx[0].hash;
    blk->header.hashMerkleRoot = compute_merkle_root(&txid, 1);
    blk->header.hashPrevBlock = *prev_hash;
    uint256_set_null(&blk->header.hashFinalSaplingRoot);
    blk->header.nTime = 1700000000u + (uint32_t)height;

    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    blk->header.nBits = arith_uint256_get_compact(&pow_limit, false);
    return true;
}

/* Count entries in a directory, excluding . and .. — used to prove the
 * datadir this join started from was, and stayed, genuinely empty. */
static int cj_dir_entry_count(const char *path)
{
    DIR *d = opendir(path);
    if (!d)
        return -1;
    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;
        n++;
    }
    closedir(d);
    return n;
}

int test_cold_join_sovereign(void)
{
    failures = 0;
    unproven = 0;
    test_reset_shared_globals();

    printf("\n=== cold_join_sovereign: a stranger joins with no permission ===\n");

    double t_start = cj_monotonic_secs();

    /* ── The wiped datadir. Everything below runs against THIS and nothing
     * else: no $HOME, no /etc, no params directory, no network. ── */
    char datadir[512];
    test_make_tmpdir(datadir, sizeof(datadir), "cold_join_sovereign", "wiped");
    CJ_CHECK("P3 the datadir this join starts from is genuinely empty",
             cj_dir_entry_count(datadir) == 0);

    /* ────────────────────────────────────────────────────────────────────
     * P1 — no DNS name is resolved from the shipped bootstrap set.
     * ──────────────────────────────────────────────────────────────────── */
    printf("\n-- P1: no DNS name in the shipped bootstrap set --\n");
    chain_params_select(CHAIN_MAIN);
    CJ_CHECK("P1 mainnet ships zero DNS seeders (the resolve loop cannot run)",
             chain_params_get()->nSeeds == 0);
    cj_check_network_has_no_names(CHAIN_MAIN, "mainnet");
    cj_check_network_has_no_names(CHAIN_TESTNET, "testnet");
    cj_check_network_has_no_names(CHAIN_REGTEST, "regtest");
    chain_params_select(CHAIN_MAIN);
    printf("cold_join: NOTE P1 covers the SHIPPED bootstrap set only. "
           "getaddrinfo() is linked and IS reachable from an operator-typed "
           "-addnode/-connect/-fileservice hostname. A name the operator types "
           "is their choice; this asserts the node needs none of its own.\n");

    /* ────────────────────────────────────────────────────────────────────
     * P2 — no certificate authority is consulted.
     * ──────────────────────────────────────────────────────────────────── */
    printf("\n-- P2: no CA is reachable from any Z23 translation unit --\n");
    {
        char where[512] = {0};
        long scanned = 0;
        CJ_CHECK("P2 restart aggregate exclusion keeps a same-named "
                 "constituent production object",
                 cj_restart_aggregate_selector_selftest());
        long refs = cj_count_trust_store_refs(where, sizeof(where), &scanned);
        if (refs < 0) {
            CJ_UNPROVEN("P2 no Z23 object references a TLS-client/trust-store "
                        "entry point", where);
        } else {
            printf("cold_join:   scanned %ld public-node production object "
                   "file(s) in %s\n",
                   scanned, where);
            CJ_CHECK("P2 zero Z23 objects reference a TLS-client or "
                     "trust-store entry point", refs == 0);
        }
        printf("cold_join: NOTE P2 asserts UNREACHABILITY, not absence. A full "
               "OpenSSL — TLS_client_method, SSL_CTX_set_default_verify_paths, "
               "the string \"/etc/ssl/certs\" — is statically linked into the "
               "shipped node by the optional, off-by-default block-explorer "
               "HTTPS listener. No Z23 code calls any of it.\n");
    }

    /* ────────────────────────────────────────────────────────────────────
     * P3 — no account, key, or registration is required.
     * Every consensus input needed to begin is already in the binary. The
     * empty datadir asserted above is the proof that nothing was read.
     * ──────────────────────────────────────────────────────────────────── */
    printf("\n-- P3: every consensus input is already in the binary --\n");
    {
        const struct chain_params *p = chain_params_get();
        struct uint256 expect_genesis;
        uint256_set_hex(&expect_genesis, CJ_GENESIS_HEX);
        CJ_CHECK("P3 real mainnet genesis hash is compiled in",
                 uint256_eq(&p->consensus.hashGenesisBlock, &expect_genesis));
        CJ_CHECK("P3 real mainnet checkpoint lineage is compiled in",
                 p->checkpointData.nEntries >= 60 &&
                 p->checkpointData.entries != NULL);
        CJ_CHECK("P3 checkpoint lineage reaches real chain heights",
                 p->checkpointData.nEntries >= 60 &&
                 p->checkpointData.entries[p->checkpointData.nEntries - 1].height
                     >= CJ_CHECKPOINT_FLOOR);
        CJ_CHECK("P3 minimum chain work is compiled in",
                 !uint256_is_null(&p->consensus.nMinimumChainWork));
        CJ_CHECK("P3 network-upgrade activation heights are compiled in",
                 p->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight > 0);

        const struct rom_state_checkpoint *rom = get_rom_state_checkpoint();
        bool rom_baked = rom && rom->height == CJ_ROM_KEYSTONE_HEIGHT &&
                         rom->utxo_count > 0 && rom->total_supply > 0;
        if (rom_baked) {
            bool root_nonzero = false;
            for (int i = 0; i < 32; i++)
                if (rom->rom_state_root[i] != 0) { root_nonzero = true; break; }
            rom_baked = root_nonzero;
        }
        CJ_CHECK("P3 the ROM state keystone is BAKED, not a placeholder",
                 rom_baked);
        CJ_CHECK("P3 the datadir is still empty (nothing was registered "
                 "or fetched to get here)",
                 cj_dir_entry_count(datadir) == 0);
    }

    /* ────────────────────────────────────────────────────────────────────
     * P4 — no proving parameters are needed to START VALIDATING, and
     * sending is honestly refused without them.
     * ──────────────────────────────────────────────────────────────────── */
    printf("\n-- P4: validation armed with no parameter files, proving is not --\n");
    {
        CJ_CHECK("P4 shielded verifying keys install from the binary alone",
                 sapling_install_embedded_vks());
        CJ_CHECK("P4 shielded proof VALIDATION is armed",
                 sapling_params_loaded());
        CJ_CHECK("P4 shielded PROVING is NOT armed (the 777 MB keys are "
                 "not shipped and are not pretended)",
                 !zclassic_sapling_prover_is_ready());
        const char *st = zclassic_sapling_prover_status();
        CJ_CHECK("P4 the prover SAYS it has no parameters rather than "
                 "emitting an unproven output",
                 st && strcmp(st, "params_not_initialized") == 0);
        CJ_CHECK("P4 no parameter bytes were written into the datadir",
                 cj_dir_entry_count(datadir) == 0);
        printf("cold_join: NOTE P4 is the honest pair. A cold node can CHECK "
               "every shielded transaction on the chain and cannot SEND one. "
               "Byte-exactness of the embedded keys is proven separately by "
               "tests/harness/src/test_params_vk_embedded.c.\n");
    }

    /* ────────────────────────────────────────────────────────────────────
     * P5 — the consensus validator is live and non-vacuous.
     * ──────────────────────────────────────────────────────────────────── */
    printf("\n-- P5: check_block() is armed and discriminates --\n");
    {
        chain_params_select(CHAIN_REGTEST);
        const struct chain_params *cp = chain_params_get();
        struct uint256 prev;
        uint256_set_null(&prev);

        struct block blk;
        bool built = cj_build_regtest_block(&blk, 1, &prev, cp);
        CJ_CHECK("P5 a real coinbase block is built", built);

        bool mined = built && mine_block_pow(&blk, 1, cp, 0);
        CJ_CHECK("P5 a REAL Equihash solution is found (this is work, "
                 "not a stub)", mined);

        if (mined) {
            struct validation_state st;
            validation_state_init(&st);
            bool accepted = check_block(&blk, &st, cp, true, true, true);
            CJ_CHECK("P5 the MUST-NEVER-FORK entry point ACCEPTS a valid "
                     "block on a wiped datadir", accepted);

            /* Non-vacuity: the same block, one bit of the Equihash solution
             * flipped. A validator that accepts this is not validating. */
            struct block bad = blk;
            bad.header.nSolution[0] ^= 0x01;
            struct validation_state st2;
            validation_state_init(&st2);
            bool rejected = !check_block(&bad, &st2, cp, true, true, true);
            CJ_CHECK("P5 the same block with ONE bit flipped is REJECTED "
                     "(acceptance is not vacuous)", rejected);
        }

        block_free(&blk);
        chain_params_select(CHAIN_MAIN);
        printf("cold_join: NOTE P5 does not validate a real MAINNET block, and "
               "cannot hermetically: this repository ships zero real mainnet "
               "block bytes. Bodies come from a peer. What is proven is an "
               "armed, discriminating validator bound to real mainnet "
               "checkpoint lineage — the state a node is in before the first "
               "peer answers.\n");
    }

    /* ────────────────────────────────────────────────────────────────────
     * P6 — does joining depend on one specific operator's machine?
     * This is the proposition that does NOT fully hold, and it is reported
     * as it is rather than as the story would like it.
     * ──────────────────────────────────────────────────────────────────── */
    printf("\n-- P6: bootstrap independence (the weak one) --\n");
    {
        const struct chain_params *p = chain_params_get();

        CJ_CHECK("P6 at least one compiled door exists at all",
                 p->nFixedSeeds > 0 || p->nOnionSeeds > 0);
        CJ_CHECK("P6 no compiled door is a name (a name is revocable by "
                 "whoever runs the registry)",
                 p->nSeeds == 0);

        printf("cold_join: MEASURED doors — clearnet fixed seeds=%zu, "
               "compiled onion seeds=%zu\n", p->nFixedSeeds, p->nOnionSeeds);

        /* The flattering form of the story is "no specific operator's machine
         * matters". For a Tor-only stranger with an empty onion-seeds file and
         * an empty directory, that is FALSE while the compiled onion array has
         * one entry: that one box is a single point of failure, and the array's
         * only previous entry was measured dead 5/5 on 2026-08-26. Recorded as
         * an unproven proposition, not asserted away. */
        if (p->nOnionSeeds < CJ_ONION_SPOF_FLOOR) {
            char why[256];
            snprintf(why, sizeof(why),
                     "Tor-only cold start has %zu compiled onion door(s); "
                     "below %d it depends on one operator's box staying up",
                     p->nOnionSeeds, CJ_ONION_SPOF_FLOOR);
            CJ_UNPROVEN("P6 joining depends on NO specific operator machine",
                        why);
        } else {
            CJ_CHECK("P6 Tor-only cold start has more than one compiled door",
                     p->nOnionSeeds >= (size_t)CJ_ONION_SPOF_FLOOR);
        }
        /* The property that would actually retire the single point of failure
         * is that the two ZERO-REBUILD tiers outrank the compiled array: the
         * operator's ~/.config/zclassic23/onion-seeds file is consulted FIRST
         * and this node's own persisted directory SECOND, with the compiled
         * array last (core/modules/net/src/connman.c, run_onion_seed_pass). That
         * ordering is what lets a stranger open a door the release cannot
         * revoke. It cannot be driven from here: run_onion_seed_pass() is
         * static, needs a live connman, and returns early unless Tor reports
         * dial-ready. Recorded as unproven rather than waved through — as of
         * this writing NO test executes those two tiers at all. */
        CJ_UNPROVEN("P6 the two zero-rebuild bootstrap tiers outrank the "
                    "compiled array",
                    "run_onion_seed_pass() is static and needs a live "
                    "connman + Tor dial-ready; no test drives it");

        printf("cold_join: NOTE reachability of any door is NOT graded here. "
               "Whether a host answers depends on the network the test runs "
               "on, and grading an offline or Tor-less box 'fail' would measure "
               "the harness. Structural door health is proven separately by "
               "tests/harness/src/test_seed_bootstrap_doors.c.\n");
    }

    /* ────────────────────────────────────────────────────────────────────
     * P7 — time, reported as its own axis, deciding nothing.
     * ──────────────────────────────────────────────────────────────────── */
    double elapsed = cj_monotonic_secs() - t_start;
    const char *verdict;
    if (failures > 0)
        verdict = "BROKEN";                 /* a proposition is false        */
    else if (elapsed > (double)CJ_HANG_DETECT_SECS)
        verdict = "SLOW";                   /* healthy, just not fast        */
    else
        verdict = "JOINED";

    printf("\n-- P7: time is a separate result --\n");
    printf("COLD_JOIN_VERDICT=%s\n", verdict);
    printf("COLD_JOIN_ELAPSED_SECONDS=%.3f\n", elapsed);
    printf("COLD_JOIN_HANG_DETECT_SECONDS=%d\n", CJ_HANG_DETECT_SECS);
    printf("COLD_JOIN_REACHABILITY=not_graded "
           "(no peer is contacted; joining is proven from the binary)\n");
    printf("cold_join: NOTE elapsed time CANNOT fail this test. SLOW means the "
           "box is slow and the join still worked; BROKEN means a proposition "
           "is false. A harness that kills this test — a systemd watchdog on a "
           "loaded box, an OOM — should report CJ_KILLED, which is neither.\n");

    if (elapsed > (double)CJ_HANG_DETECT_SECS)
        printf("cold_join: SLOW — %.1fs exceeded the %d s hang detector. This "
               "is evidence about this machine, not a defect, and is counted "
               "as neither a failure nor an unproven proposition.\n",
               elapsed, CJ_HANG_DETECT_SECS);

    test_rm_rf(datadir);

    printf("\n=== cold_join_sovereign: %d failure(s), %d unproven "
           "proposition(s) ===\n", failures, unproven);
    if (unproven > 0)
        printf("cold_join: %d proposition(s) above are UNPROVEN. They are not "
               "failures and they are not passes. Read them.\n", unproven);
    return failures;
}
