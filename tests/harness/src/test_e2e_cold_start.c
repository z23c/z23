/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_e2e_cold_start: hermetic end-to-end slice of the two-step cold-sync
 * recipe. A small synthetic legacy-shaped datadir feeds the real import path
 * (snapshot_import_block_index) and the real hydrate entry point
 * (load_block_index_from_blocks_table), in-process. It pins the
 * import->hydrate data seam that the separate import and hydrate tests
 * do not cover together.
 *
 * Coverage:
 *   (1) N=300 hash-linked headers with real bodies (write_block_to_disk),
 *       one read back via read_block_from_disk_pread.
 *   (2) Cold start of a fresh datadir with header_only=true, then hydrate:
 *       the map has N entries and the tip pprev-walks N hops to the root.
 *   (3) A poisoned source row (merkle root mutated) is quarantined at import
 *       by import_row_verify, the import continues, the quarantine counter
 *       advances, and the loader declines to bridge the gap.
 *
 * Not covered: a forked `z23` serving boot (boot loader-rung
 * ordering, `z23 status`), left to the heavy self-skipping child-process
 * slices such as test_importblockindex_cli_dispatch.c.
 *
 * make t ONLY=e2e_cold_start
 */

#include "test/test_core.h"
#include "coins/undo.h"

#include "chain/chain.h"                 /* BLOCK_HAVE_DATA / BLOCK_VALID_* */
#include "chain/chainparams.h"           /* chain_params_get / consensus.powLimit */
#include "controllers/snapshot_controller.h"
#include "core/arith_uint256.h"
#include "services/block_index_loader.h"
#include "storage/block_index_db.h"
#include "storage/dbwrapper.h"
#include "storage/disk_block_io.h"
#include "primitives/block.h"
#include "validation/main_state.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define E2E_N_BLOCKS   300
#define E2E_NO_POISON  (-1)

/* A small non-empty Equihash-solution stand-in: blocks_row_to_header
 * rejects a zero-length solution. Small so the per-row PoW mine stays cheap;
 * rows below the ROM checkpoint skip check_equihash_solution. */
#define E2E_SOLUTION_SIZE  8

#define E2E_CHECK(name, expr) do {                              \
    printf("e2e_cold_start: %s... ", (name));                   \
    if ((expr)) printf("OK\n");                                 \
    else { printf("FAIL\n"); failures++; }                      \
} while (0)

struct e2e_fixture {
    struct uint256         hash[E2E_N_BLOCKS];
    struct disk_block_pos  pos[E2E_N_BLOCKS];
};

static int e2e_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* The mainnet powLimit as compact nBits, the easiest target
 * CheckProofOfWork accepts (as in GetNextWorkRequired() genesis,
 * core/chainparams/src/pow.c). */
static uint32_t e2e_pow_limit_bits(void)
{
    const struct chain_params *cp = chain_params_get();
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    return arith_uint256_get_compact(&pow_limit, false);
}

/* Grind nNonce until dbi's header hash satisfies the PoW target at `bits`,
 * writing the hash to *out_hash. import_row_verify hash-binds and
 * PoW-checks every row. nTime is left intact for the body round-trip.
 * ~1/8192 expected tries at powLimit, bounded so a break fails loudly.
 * Compares against the decoded target directly to avoid CheckProofOfWork's
 * per-miss logging. */
static bool e2e_mine_pow(struct disk_block_index *dbi, uint32_t bits,
                         struct uint256 *out_hash)
{
    bool neg = false, overflow = false;
    struct arith_uint256 target;
    arith_uint256_set_compact(&target, bits, &neg, &overflow);
    if (neg || overflow || arith_uint256_is_zero(&target))
        return false;

    dbi->nBits = bits;
    for (uint32_t tries = 0; tries < 8000000u; tries++) {
        memset(dbi->nNonce.data, 0, 32);
        dbi->nNonce.data[0] = (uint8_t)(tries & 0xff);
        dbi->nNonce.data[1] = (uint8_t)((tries >> 8) & 0xff);
        dbi->nNonce.data[2] = (uint8_t)((tries >> 16) & 0xff);
        dbi->nNonce.data[3] = (uint8_t)((tries >> 24) & 0xff);
        disk_block_index_get_hash(dbi, out_hash);
        struct arith_uint256 hash_arith;
        uint256_to_arith(&hash_arith, out_hash);
        if (arith_uint256_compare(&hash_arith, &target) <= 0)
            return true;
    }
    return false;
}

/* Build a legacy-shaped source datadir: `src_dir/blocks/index` (LevelDB,
 * disk_block_index_serialize() format) plus `blocks/blkNNNNN.dat` bodies
 * (write_block_to_disk()) for N hash-linked blocks. Each key is the real
 * header hash (disk_block_index_get_hash) and each row carries
 * minimum-difficulty PoW, as import_row_verify requires.
 *
 * If poison_height >= 0 that row's stored hashMerkleRoot is corrupted after
 * mining, keeping its key so linkage stays intact but the row no longer
 * hash-binds; it is quarantined at import.
 *
 * fx->hash[h] and fx->pos[h] record each block's hash and body position. */
static bool e2e_build_fixture_chain(const char *src_dir, int n,
                                    int poison_height,
                                    struct e2e_fixture *fx)
{
    char idx_dir[512];
    snprintf(idx_dir, sizeof(idx_dir), "%s/blocks/index", src_dir);

    struct db_wrapper dbw;
    if (!db_wrapper_open(&dbw, idx_dir, 4 << 20, false, true)) {
        fprintf(stderr, "e2e_build_fixture_chain: db_wrapper_open failed: %s\n",
                idx_dir);
        return false;
    }

    static const unsigned char msg_start[4] = { 0x24, 0xe9, 0x27, 0x64 };
    const uint32_t pow_bits = e2e_pow_limit_bits();
    struct uint256 prev;
    memset(&prev, 0, sizeof(prev));
    bool ok = true;

    for (int h = 0; h < n && ok; h++) {
        /* Build the LevelDB record first and mine PoW into it; positions
         * are not header fields and are filled after mining. */
        struct disk_block_index dbi;
        disk_block_index_init(&dbi);
        dbi.nHeight = h;
        dbi.hashPrev = prev;
        dbi.nStatus = (unsigned int)(BLOCK_VALID_TRANSACTIONS |
                                     BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
        dbi.nTx = 1;
        dbi.nVersion = 4;
        memset(dbi.hashMerkleRoot.data, 0, 32);
        dbi.hashMerkleRoot.data[0] = 0xBB;
        dbi.hashMerkleRoot.data[1] = (uint8_t)(h & 0xff);
        dbi.hashMerkleRoot.data[2] = (uint8_t)((h >> 8) & 0xff);
        dbi.hashMerkleRoot.data[31] = 0x02;
        memset(dbi.hashFinalSaplingRoot.data, 0, 32);
        dbi.nTime = 1231006505u + (uint32_t)h;
        memset(dbi.nSolution, 0x40 + (h & 0x3f), E2E_SOLUTION_SIZE);
        dbi.nSolutionSize = E2E_SOLUTION_SIZE;
        dbi.nSaplingValue = (int64_t)h * 1000;

        struct uint256 real_hash;
        if (!e2e_mine_pow(&dbi, pow_bits, &real_hash)) {
            fprintf(stderr, "e2e_build_fixture_chain: PoW mine failed h=%d\n", h);
            ok = false;
            break;
        }

        struct block b;
        block_init(&b);
        b.header.nVersion = dbi.nVersion;
        b.header.hashPrevBlock = dbi.hashPrev;
        b.header.hashMerkleRoot = dbi.hashMerkleRoot;
        b.header.hashFinalSaplingRoot = dbi.hashFinalSaplingRoot;
        b.header.nTime = dbi.nTime;
        b.header.nBits = dbi.nBits;
        b.header.nNonce = dbi.nNonce;
        memcpy(b.header.nSolution, dbi.nSolution, dbi.nSolutionSize);
        b.header.nSolutionSize = dbi.nSolutionSize;

        b.num_vtx = 1;
        b.vtx = zcl_calloc(1, sizeof(struct transaction), "e2e_fixture_vtx");
        if (!b.vtx) {
            fprintf(stderr, "e2e_build_fixture_chain: vtx alloc failed h=%d\n", h);
            block_free(&b);
            ok = false;
            break;
        }
        transaction_init(&b.vtx[0]);
        if (!transaction_alloc(&b.vtx[0], 1, 1)) {
            fprintf(stderr, "e2e_build_fixture_chain: transaction_alloc "
                    "failed h=%d\n", h);
            block_free(&b);
            ok = false;
            break;
        }
        b.vtx[0].vin[0].sequence = 0xffffffff;
        b.vtx[0].vout[0].value = 10 * COIN;

        struct disk_block_pos pos = { .nFile = -1, .nPos = 0 };
        if (!write_block_to_disk(&b, &pos, src_dir, msg_start)) {
            fprintf(stderr, "e2e_build_fixture_chain: write_block_to_disk "
                    "failed h=%d\n", h);
            block_free(&b);
            ok = false;
            break;
        }

        dbi.nFile = pos.nFile;
        dbi.nDataPos = pos.nPos;
        dbi.nUndoPos = pos.nPos + 500u;

        struct disk_block_index dbi_stored = dbi;
        if (h == poison_height) {
            /* Corrupt the STORED VALUE only; the key (the mined hash, used
             * for chain linkage) is untouched, so the row no longer
             * hash-binds to its content. */
            memset(dbi_stored.hashMerkleRoot.data, 0xEE, 32);
        }

        struct byte_stream s;
        stream_init(&s, 2048);
        bool ser_ok = disk_block_index_serialize(&dbi_stored, &s) && !s.error;
        if (ser_ok) {
            char key[33];
            key[0] = 'b';
            memcpy(key + 1, real_hash.data, 32);
            ser_ok = db_write(&dbw, key, sizeof(key), (const char *)s.data,
                              s.size, false);
        }
        stream_free(&s);
        if (!ser_ok) {
            fprintf(stderr, "e2e_build_fixture_chain: db_write failed h=%d\n", h);
            block_free(&b);
            ok = false;
            break;
        }

        fx->hash[h] = real_hash;
        fx->pos[h] = pos;
        prev = real_hash;
        block_free(&b);
    }

    db_wrapper_close(&dbw);
    return ok;
}

/* Round-trip one body: the fixture bodies are real write_block_to_disk()
 * output, not just header metadata. */
static bool e2e_body_reads_back(const char *src_dir,
                                const struct e2e_fixture *fx, int height)
{
    struct block b;
    if (!read_block_from_disk_pread(&b, &fx->pos[height], src_dir))
        return false;
    bool ok = b.header.nTime == 1231006505u + (uint32_t)height &&
              b.num_vtx == 1;
    block_free(&b);
    return ok;
}

/* Probe the hydrated clean map for checks (2e)/(2f): walk the tip's pprev
 * chain back towards the root (bounded, as before) and read the mid-height
 * row's status flags. Writes the two outcomes through the out-params; the
 * caller prints the checks. */
static void e2e_probe_hydrated_tip_and_mid_row(struct main_state *ms,
                                               struct e2e_fixture *fx,
                                               bool *tip_ok,
                                               bool *honest_header_only)
{
    struct block_index *tip = block_map_find(&ms->map_block_index,
                                             &fx->hash[E2E_N_BLOCKS - 1]);
    int walk = 0;
    struct block_index *cur = tip;
    while (cur && walk < E2E_N_BLOCKS + 5) { walk++; cur = cur->pprev; }
    *tip_ok = tip && tip->nHeight == E2E_N_BLOCKS - 1 &&
              walk == E2E_N_BLOCKS;

    struct block_index *mid = block_map_find(&ms->map_block_index,
                                             &fx->hash[E2E_N_BLOCKS / 2]);
    *honest_header_only = mid &&
        ((mid->nStatus & BLOCK_VALID_MASK) == BLOCK_VALID_TREE) &&
        !(mid->nStatus & BLOCK_HAVE_DATA);
}

/* Scenario A, checks (1)-(2f): build the clean legacy-shaped source
 * datadir, import it into a fresh target through the real path, hydrate
 * through the real boot entry point and check the hydrated map. Returns
 * the number of failed checks. */
static int e2e_run_clean_import_and_hydrate_scenario(const char *base)
{
    int failures = 0;

    char src_dir[340];
    snprintf(src_dir, sizeof(src_dir), "%s/legacy-src-clean", base);
    e2e_mkdir_p(src_dir);

    struct e2e_fixture *fx = zcl_malloc(sizeof(*fx), "e2e_fixture_clean");
    bool built = fx && e2e_build_fixture_chain(src_dir, E2E_N_BLOCKS,
                                               E2E_NO_POISON, fx);
    E2E_CHECK("(1) build source datadir: N=300 hash-linked headers+real "
              "bodies (disk_block_index_serialize + write_block_to_disk)",
              built);

    bool body_ok = built &&
        e2e_body_reads_back(src_dir, fx, E2E_N_BLOCKS - 1);
    E2E_CHECK("(1b) a source body round-trips via read_block_from_disk_"
              "pread (bodies are real, not just header metadata)", body_ok);

    char target_db[380];
    snprintf(target_db, sizeof(target_db), "%s/node_clean.db", base);
    int count = -1;
    bool import_ok = built && snapshot_import_block_index(
        src_dir, target_db, /*header_only=*/true, &count);
    E2E_CHECK("(2a) real import path: snapshot_import_block_index("
              "header_only=true — the literal argv[1] --importblockindex "
              "CLI shape) imports all N headers",
              import_ok && count == E2E_N_BLOCKS);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool opened = import_ok && node_db_open(&ndb, target_db);
    E2E_CHECK("(2b) fresh target node.db opens after import", opened);

    struct main_state ms;
    main_state_init(&ms);
    bool hydrate_ok = false;
    if (opened)
        hydrate_ok = load_block_index_from_blocks_table(&ndb, &ms).ok;
    E2E_CHECK("(2c) real hydrate-at-boot entry point "
              "(load_block_index_from_blocks_table) hydrates the map "
              "from the freshly-imported `blocks` table", hydrate_ok);

    bool size_ok = hydrate_ok &&
                   ms.map_block_index.size == (size_t)E2E_N_BLOCKS;
    E2E_CHECK("(2d) hydrated map size == N (the fresh-datadir "
              "header-hydration hole this slice pins closed)", size_ok);

    bool tip_ok = false;
    bool honest_header_only = false;
    if (size_ok)
        e2e_probe_hydrated_tip_and_mid_row(&ms, fx, &tip_ok,
                                           &honest_header_only);
    E2E_CHECK("(2e) tip linkage reaches the fixture tip (pprev walks "
              "exactly N hops to the fixture root)", tip_ok);
    E2E_CHECK("(2f) fidelity boundary: header-only import installs "
              "entries HONESTLY (BLOCK_VALID_TREE, no HAVE_DATA) even "
              "though the SOURCE datadir carries real bodies",
              honest_header_only);

    if (opened) node_db_close(&ndb);
    main_state_free(&ms);
    free(fx);
    return failures;
}

/* Scenario B, check (3c): open the freshly-imported poisoned target,
 * hydrate it through the real boot entry point and prove the poisoned row
 * never seeds a map entry while the quarantined gap is left unbridged.
 * Returns the number of failed checks. */
static int e2e_hydrate_poisoned_target_and_check_gap(char *target_db,
                                                     struct e2e_fixture *fx,
                                                     int poison_h,
                                                     bool import_ok)
{
    int failures = 0;

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool opened = import_ok && node_db_open(&ndb, target_db);

    struct main_state ms;
    main_state_init(&ms);
    bool hydrate_ok = false, poison_absent = false, gap_not_bridged = false;
    size_t hydrated = 0;
    if (opened) {
        struct zcl_result hydrate =
            load_block_index_from_blocks_table(&ndb, &ms);
        hydrate_ok = hydrate.ok;
        hydrated = ms.map_block_index.size;
        /* The poisoned height's hash must be absent from the map. */
        poison_absent = block_map_find(&ms.map_block_index,
                                       &fx->hash[poison_h]) == NULL;
        /* The loader declines to bridge the quarantined gap: the missing
         * height's child keeps pprev NULL. */
        struct block_index *child = block_map_find(&ms.map_block_index,
                                                   &fx->hash[poison_h + 1]);
        gap_not_bridged = child && child->pprev == NULL;
    }
    E2E_CHECK("(3c) the poisoned SOURCE row never seeds a map entry: "
              "hydrate loads the surviving N-1 rows (.ok), the poisoned "
              "height is ABSENT from the map, and the loader declines to "
              "bridge the gap (its child's pprev stays NULL) — no partial "
              "linked map is seeded across the poison",
              opened && hydrate_ok &&
              hydrated == (size_t)(E2E_N_BLOCKS - 1) &&
              poison_absent && gap_not_bridged);

    if (opened) node_db_close(&ndb);
    main_state_free(&ms);
    return failures;
}

/* Scenario B, checks (3a)-(3c): build a source datadir with one poisoned
 * row, import it through the real path while watching the quarantine
 * counter, then hydrate the target and check the poisoned row stayed out.
 * Returns the number of failed checks. */
static int e2e_run_poison_quarantine_scenario(const char *base)
{
    int failures = 0;

    char src_dir[340];
    snprintf(src_dir, sizeof(src_dir), "%s/legacy-src-poison", base);
    e2e_mkdir_p(src_dir);

    struct e2e_fixture *fx = zcl_malloc(sizeof(*fx), "e2e_fixture_poison");
    int poison_h = E2E_N_BLOCKS / 2;
    bool built = fx && e2e_build_fixture_chain(src_dir, E2E_N_BLOCKS,
                                               poison_h, fx);
    E2E_CHECK("(3a) build source datadir with ONE poisoned row "
              "(h=N/2's stored merkle_root corrupted; its key stays the "
              "originally-computed hash, matching real bit-flip "
              "corruption)", built);

    char target_db[380];
    snprintf(target_db, sizeof(target_db), "%s/node_poison.db", base);
    uint64_t q_before = snapshot_import_block_index_quarantine_total();
    int count = -1;
    bool import_ok = built && snapshot_import_block_index(
        src_dir, target_db, /*header_only=*/true, &count);
    uint64_t q_after = snapshot_import_block_index_quarantine_total();
    E2E_CHECK("(3b) lane C4 hash-binds every row at import: the poisoned "
              "row (its stored merkle_root no longer hashes to its LevelDB "
              "key) is QUARANTINED at import — the batch CONTINUES (import "
              "ok), count == N-1, and the quarantine counter advances by "
              "exactly 1; it never enters `blocks`",
              import_ok && count == E2E_N_BLOCKS - 1 &&
              (q_after - q_before) == 1);

    failures += e2e_hydrate_poisoned_target_and_check_gap(target_db, fx,
                                                          poison_h,
                                                          import_ok);
    free(fx);
    return failures;
}

int test_e2e_cold_start(void)
{
    int failures = 0;
    printf("\n=== e2e cold start (real --importblockindex path + real "
           "hydrate-at-boot entry point) ===\n");

    char base[300];
    test_make_tmpdir(base, sizeof(base), "e2e_cold_start", "main");

    /* ── Scenario A: clean fixture — import + hydrate reach the tip ────── */
    failures += e2e_run_clean_import_and_hydrate_scenario(base);

    /* ── Scenario B: a poisoned SOURCE row is quarantined at IMPORT and
     *    never seeds a map entry ─────────────────────────────────────────── */
    failures += e2e_run_poison_quarantine_scenario(base);

    test_rm_rf(base);

    if (failures == 0)
        printf("e2e_cold_start OK (real import -> real hydrate seam: clean "
               "fixture reaches the tip, poisoned row quarantined at import "
               "and never seeds a map entry)\n");
    return failures;
}
