/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_e2e_cold_start — hermetic END-TO-END slice for the two-step cold-sync
 * recipe (CLAUDE.md "Tenacity & recovery"): a SMALL synthetic legacy-shaped
 * source datadir feeds the REAL import path AND the REAL hydrate-at-boot
 * service entry point, in-process, at commit time.
 *
 * WHY THIS EXISTS
 * ----------------
 * "unit tests green, cold start broken" is a real regression class here: the
 * fresh-datadir header-hydration hole (--importblockindex fills node.db
 * `blocks` but every other loader rung left a genesis-only map, so a freshly
 * imported node served H*=0) was found by a LIVE run, not by CI, even though
 * both halves of the pipe already had unit coverage individually:
 *   - test_importblockindex_roundtrip.c / test_importblockindex_cli_dispatch.c
 *     prove the import half in isolation.
 *   - test_block_index_loader.c cases 15/16 prove the hydrate half in
 *     isolation, but build the `blocks` table by hand
 *     (bih_insert_header_row), never by running the real importer.
 * Neither test drives the SEAM: a poisoned or well-formed row as the real
 * importer would actually leave it. This slice closes that gap by chaining
 * the two REAL functions the two-step recipe and the `-cold-start` driver
 * both call:
 *   snapshot_import_block_index()             (engine/controllers/src/
 *                                               snapshot_controller_import.c)
 *   load_block_index_from_blocks_table()       (engine/services/src/
 *                                               block_index_loader.c)
 * against a synthetic legacy `blocks/index` LevelDB + blk*.dat body files
 * built with the REAL on-disk wire formats (disk_block_index_serialize(),
 * write_block_to_disk()) — not hand-rolled bytes.
 *
 * COVERAGE
 * --------
 *   (1) Build a source datadir with N=300 hash-linked headers AND real block
 *       bodies (write_block_to_disk — the same function connect_block uses).
 *       One block is read back via read_block_from_disk_pread to prove the
 *       bodies are genuine, not just header metadata.
 *   (2) Cold-start a FRESH datadir: snapshot_import_block_index() with
 *       header_only=true — the literal argv[1] `--importblockindex <src>`
 *       CLI shape (routing already proven live by
 *       test_importblockindex_cli_dispatch.c) — then
 *       load_block_index_from_blocks_table() against that fresh node.db.
 *       Asserts the map hydrates to N entries and tip linkage pprev-walks
 *       exactly N hops to the fixture root — the exact property the live
 *       incident lacked (a freshly-imported node stuck at H*=0).
 *   (3) A poisoned SOURCE row (LevelDB value's hashMerkleRoot mutated so its
 *       content no longer hashes to its own claimed key) is QUARANTINED at
 *       import by lane C4's per-row hash-bind check (import_row_verify) — the
 *       bulk import CONTINUES, the poisoned row never enters `blocks`, and the
 *       quarantine counter advances. The resulting hydrate loads the surviving
 *       rows but the poisoned height is absent and the loader honestly
 *       declines to bridge the gap — a poisoned source row seeds no partial
 *       map. (Before C4 the poison was copied verbatim and caught only at
 *       hydrate; C4 moved the same hash-bind one stage earlier.)
 *
 * FIDELITY GAP (documented, not closed here)
 * -------------------------------------------
 * This slice drives the two real service entry points directly, in-process
 * — it does NOT fork a full `zclassic23` serving boot (app_init, the eight
 * reducer stages, RPC/P2P listeners) against the cold-started datadir. A
 * full child-process boot would additionally prove: the boot loader-rung
 * ordering actually calls load_block_index_from_blocks_table when the
 * earlier rungs see a genesis-only map (engine/composition/src/boot_services.c wiring),
 * `z23 status`/RPC surfaces the hydrated tip height, and the process
 * stays up. That is deliberately left to the existing heavy, self-skipping
 * child-process slices (test_importblockindex_cli_dispatch.c's pattern:
 * skip unless build/bin/zclassic23 exists and is newer than its witness
 * sources) — spawning a full serving node (port/RPC binding, background
 * validation threads, shutdown sequencing) inside this fast in-process test
 * risks exactly the flakiness/runtime cost the sibling heavy slices already
 * gate behind opt-in env vars. If the boot-ordering wiring regresses,
 * docs/AGENT_TRAPS.md + the live `z23 status` check remain the
 * second line of defense; this slice's job is pinning the import->hydrate
 * DATA seam, which is exactly the seam the live incident broke on.
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

/* A small NON-EMPTY Equihash-solution stand-in. It must be > 0 bytes: the
 * hydrate loader (blocks_row_to_header, engine/services/src/
 * block_index_blocks_hydrate.c) rejects a zero-length solution as an
 * unusable header. It is kept small (not the real 1344-byte size) purely so
 * the per-row PoW mine below hashes a short header and stays cheap — these
 * synthetic rows are below the ROM checkpoint, so import_row_verify never
 * runs check_equihash_solution on them (only the hash-bind + PoW-target
 * check, which is content-agnostic about the solution). */
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

/* The mainnet powLimit as compact nBits — the EASIEST target
 * CheckProofOfWork will legally accept (a weaker/easier target is rejected
 * outright), so it gives a synthetic fixture row the best odds of an
 * inexpensive "mine". The SAME value the real GetNextWorkRequired() genesis
 * case uses (core/chainparams/src/pow.c). */
static uint32_t e2e_pow_limit_bits(void)
{
    const struct chain_params *cp = chain_params_get();
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    return arith_uint256_get_compact(&pow_limit, false);
}

/* Grind nNonce until dbi's real header hash satisfies the PoW target at
 * `bits`, writing the winning hash to *out_hash. Lane C4 made the importer
 * hash-bind AND PoW-target-check every row (import_row_verify), so a fixture
 * row must carry genuine (minimum-difficulty) proof-of-work exactly as a real
 * zclassicd datadir row already does for its network difficulty — a random
 * placeholder hash is now quarantined "high-hash". Grinding nNonce (not
 * nTime) leaves the header's nTime intact so the body round-trip check (1b)
 * still holds. ~1/8192 expected tries at the mainnet powLimit; bounded so a
 * structural break fails loudly instead of hanging. Compares against the
 * decoded target directly (the same arith compare CheckProofOfWork does)
 * rather than calling CheckProofOfWork per attempt, which logs every miss. */
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

/* Build a real legacy-shaped source datadir: `src_dir/blocks/index` (a
 * LevelDB block-tree, real disk_block_index_serialize() wire format) plus
 * real `src_dir/blocks/blkNNNNN.dat` bodies (write_block_to_disk() — the
 * same writer connect_block uses), for N hash-linked blocks. Each block's
 * LevelDB key is its REAL block-header PoW-style hash (computed via
 * disk_block_index_get_hash, which reconstructs and hashes the identical
 * fields load_block_index_from_blocks_table later re-derives), so a
 * downstream hash-bind check genuinely passes for every unpoisoned row.
 *
 * Every row also carries GENUINE minimum-difficulty proof-of-work: nNonce is
 * ground (e2e_mine_pow) until the header hash satisfies CheckProofOfWork at
 * the mainnet powLimit. This is mandatory since lane C4 — the importer now
 * hash-binds AND PoW-target-checks every row (import_row_verify), quarantining
 * a placeholder-hash / no-PoW row as "high-hash", exactly as a real zclassicd
 * datadir row already satisfies its own network difficulty.
 *
 * If poison_height >= 0, that ONE row's STORED VALUE gets a corrupted
 * hashMerkleRoot AFTER mining — its key (the mined hash children link against
 * via hashPrev, exactly as real corruption would leave it) is left as the
 * correct, originally-computed hash, so chain linkage stays structurally
 * intact but that one row no longer hash-binds to its own content. With lane
 * C4 that row is now quarantined at IMPORT (it never enters `blocks`), one
 * layer earlier than the old verbatim-copy-then-refuse-at-hydrate path.
 *
 * fx->hash[h] records every block's real computed hash for the caller's
 * later assertions; fx->pos[h] records its real body position. */
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
        /* Build the LevelDB record (the CDiskBlockIndex the importer reads)
         * first, then mine genuine minimum-difficulty PoW into it; the block
         * body below is written with a header consistent with the mined
         * record. Positions (nFile/nDataPos/nUndoPos) are not header fields,
         * so they are filled AFTER mining without disturbing the hash. */
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
            /* Corrupt the STORED VALUE only — the key (real_hash, used for
             * chain linkage below) is untouched, matching how a bit-flip /
             * partial write would corrupt a real legacy datadir. The mined
             * PoW-valid hash stays the key; only the stored merkle_root is
             * mutated, so this row no longer hash-binds to its own content. */
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

/* Round-trip one body: proves the source datadir's bodies are REAL
 * write_block_to_disk() output, not just header metadata — the fixture
 * genuinely has "headers+bodies", matching what a real legacy zclassicd
 * datadir looks like. */
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

int test_e2e_cold_start(void)
{
    int failures = 0;
    printf("\n=== e2e cold start (real --importblockindex path + real "
           "hydrate-at-boot entry point) ===\n");

    char base[300];
    test_make_tmpdir(base, sizeof(base), "e2e_cold_start", "main");

    /* ── Scenario A: clean fixture — import + hydrate reach the tip ────── */
    {
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
        if (size_ok) {
            struct block_index *tip = block_map_find(&ms.map_block_index,
                                                      &fx->hash[E2E_N_BLOCKS - 1]);
            int walk = 0;
            struct block_index *cur = tip;
            while (cur && walk < E2E_N_BLOCKS + 5) { walk++; cur = cur->pprev; }
            tip_ok = tip && tip->nHeight == E2E_N_BLOCKS - 1 &&
                     walk == E2E_N_BLOCKS;

            struct block_index *mid = block_map_find(&ms.map_block_index,
                                                      &fx->hash[E2E_N_BLOCKS / 2]);
            honest_header_only = mid &&
                ((mid->nStatus & BLOCK_VALID_MASK) == BLOCK_VALID_TREE) &&
                !(mid->nStatus & BLOCK_HAVE_DATA);
        }
        E2E_CHECK("(2e) tip linkage reaches the fixture tip (pprev walks "
                  "exactly N hops to the fixture root)", tip_ok);
        E2E_CHECK("(2f) fidelity boundary: header-only import installs "
                  "entries HONESTLY (BLOCK_VALID_TREE, no HAVE_DATA) even "
                  "though the SOURCE datadir carries real bodies",
                  honest_header_only);

        if (opened) node_db_close(&ndb);
        main_state_free(&ms);
        free(fx);
    }

    /* ── Scenario B: a poisoned SOURCE row is caught at IMPORT (lane C4),
     *    never seeding a map entry ──────────────────────────────────────────
     *
     * Before lane C4 the importer copied every LevelDB row verbatim and the
     * poison was only caught at hydrate (which then refused the WHOLE table).
     * C4 moved that hash-bind check to import time: the poisoned row now fails
     * hash-bind and is QUARANTINED at import — it never enters `blocks`. The
     * invariant this slice pins is unchanged ("a poisoned source row never
     * seeds a partial map"); only WHICH layer enforces it moved one stage
     * earlier. (The hydrate loader is itself hardened by J5 to per-row
     * quarantine rather than whole-table refusal, so the old .ok==false /
     * size==0 assertion no longer models either layer — see
     * block_index_blocks_hydrate.c.) ──────────────────────────────────────── */
    {
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
            /* The poisoned height's hash (its LevelDB key = the mined,
             * PoW-valid hash) must be ABSENT — the corrupt source row seeded
             * no map entry. */
            poison_absent = block_map_find(&ms.map_block_index,
                                           &fx->hash[poison_h]) == NULL;
            /* Defense-in-depth: the loader honestly declines to bridge the gap
             * the quarantine left — the child of the missing height links to a
             * hash that is not in the map, so its pprev stays NULL rather than
             * fabricating a chain across the hole. */
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
        free(fx);
    }

    test_rm_rf(base);

    if (failures == 0)
        printf("e2e_cold_start OK (real import -> real hydrate seam: clean "
               "fixture reaches the tip, poisoned row quarantined at import "
               "and never seeds a map entry)\n");
    return failures;
}
