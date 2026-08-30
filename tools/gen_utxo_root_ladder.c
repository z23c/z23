/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gen_utxo_root_ladder: one-shot tool that reads the per-boundary UTXO
 * roots this node's own locally validated fold already recorded (coins_kv
 * boundary_root store, keyed "mmb_utxo_root:<height>" in progress_meta —
 * see lib/storage/src/coins_kv.c:548-589) at stride heights and emits
 *
 *   lib/chain/include/chain/utxo_root_ladder.h  (declarations — stable)
 *   lib/chain/src/utxo_root_ladder.c            (table + lookup)
 *
 * WHY A NODE.DB READER, NOT AN RPC CLIENT (unlike gen_sha3_windows):
 * zclassicd's gettxoutsetinfo only reports the UTXO set at the CURRENT
 * tip — there is no RPC to ask "what was the UTXO root at historical
 * height H". Historical boundary roots exist ONLY in a node's own
 * coins_kv boundary-root store, written once by the live connect path
 * as its local fold passed each MMR_COMMITMENT_INTERVAL-aligned
 * height (app/models/src/mmb_leaf_store.c:180-191). So the ladder's
 * source of truth is a copy of a zclassic23 datadir, not a JSON-RPC peer.
 *
 * TWO FILES PER DATADIR: block hashes live in `node.db` (`blocks` table);
 * boundary UTXO roots live in the SEPARATE kernel store `consensus.db`
 * (`progress_meta` table, key "mmb_utxo_root:<height>" — see
 * lib/storage/src/consensus_db.c, coins_kv.c:548-589). Pre-flip datadirs
 * kept that table in `progress.kv` instead; `--source-progress-kv=`/
 * `--second-progress-kv=` remain accepted as aliases of
 * `--source-kernel-db=`/`--second-kernel-db=` so old runbooks still work.
 * This tool ATTACHes the sibling kernel-db copy onto the node.db
 * connection (the same technique tools/export_snapshot.c uses to join
 * sidecar files) so one connection can join both.
 *
 * The blockchain is immutable history: once a stride height's boundary
 * root is folded and independently cross-checked, it is free to keep
 * forever, the same doctrine as sha3_windows.
 *
 * CROSS-CHECKS PERFORMED:
 *   (a) The one existing zclassicd-verified anchor (SHA3 UTXO checkpoint,
 *       lib/chain/src/checkpoints.c, height 3,056,758) is always included
 *       as its own ladder rung (provenance=CHECKPOINT), and this tool
 *       cross-checks the compiled checkpoint's block_hash against the
 *       SOURCE db's own blocks table at that exact height (a plain block
 *       hash, not boundary-aligned, is available at ANY height).
 *   (b) In-binary PoW checkpoint headers (chainparams.c mainnet_checkpoints,
 *       every 50,000 blocks) DO carry real hashes: the static initializer
 *       (chainparams.c:18-82) is 63 `{{0}}` placeholders, but
 *       init_main_params() overwrites every one of them via uint256_set_hex
 *       (chainparams.c:293-421) before chain_params_get() hands the table
 *       out, so at RUNTIME all 63 are populated (re-verified 2026-08-24;
 *       pinned by the test_consensus_rule_sweep group). This tool does not
 *       consume them today — wiring that cross-check in is open work, not a
 *       missing data source.
 *   (c) Dual-source: pass --second-db=<copy of an independently-folded
 *       node.db> (e.g. a from-genesis anchor-mint datadir) and this tool
 *       cross-checks every stride's block_hash AND utxo_root against it.
 *       Agreement -> provenance=DUAL. A real mismatch (same block hash,
 *       different utxo_root, or a different block hash entirely) is
 *       treated as a fatal divergence: this tool refuses to emit ANY
 *       output rather than lock a compromised table, and prints every
 *       divergence found (it keeps scanning after the first one so a
 *       single run surfaces the whole picture).
 *
 * DENSE LAYER (optional, --leaf-store=<path to mmb_leaves.bin>):
 * recomputes mmb_root() from the SAME leaf hashes the live MMB pipeline
 * produced (app/models/src/mmb_leaf_store.c), up to one pinned height,
 * and locks the result as ONE compiled constant
 * (g_utxo_root_ladder_dense_height / g_utxo_root_ladder_dense_mmb_root).
 * This is a clean read-side reuse: mmb_leaves.bin is a flat file of
 * 32-byte leaf hashes (one per height, in order) and mmb_append_hash /
 * mmb_root (lib/chain/src/mmb.c) are pure functions with no DB or app
 * dependency, so no invasive plumbing was needed.
 *
 * Usage:
 *   gen_utxo_root_ladder <source_node_db_copy> \
 *       --source-kernel-db=PATH \
 *       [--second-db=PATH] [--second-kernel-db=PATH] [--leaf-store=PATH] \
 *       [--stride=N] [--max-height=N] [--dense-height=N] \
 *       [--immutable-source] \
 *       [--out-h=PATH] [--out-c=PATH]
 *
 * (`--source-progress-kv=`/`--second-progress-kv=` still work as aliases
 * for pre-flip datadirs whose kernel store is still progress.kv.)
 *
 * The operator ALWAYS points this at a COPY (never a live datadir) —
 * see docs/work/ and the golden-height ladder lane notes.
 *
 * Links only standalone libs: lib/chain/src/mmb.c (pure, no DB) +
 * lib/sha3/src/sha3.c (mmb.c's own dependency) + libsqlite3.a.
 * No node libs, no Tor, no RPC. */

#define _POSIX_C_SOURCE 200809L

#include "chain/mmb.h"
#include "chain/mmr.h"          /* MMR_COMMITMENT_INTERVAL */

#include <sqlite3.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEFAULT_OUT_H "lib/chain/include/chain/utxo_root_ladder.h"
#define DEFAULT_OUT_C "lib/chain/src/utxo_root_ladder.c"
#define DEFAULT_STRIDE 100000
#define MAX_ENTRIES 128   /* generous: ~3.1M/100000 strides + 1 checkpoint rung */

/* Independently re-stated from lib/chain/src/checkpoints.c
 * (get_sha3_utxo_checkpoint's g_sha3_checkpoint) so this standalone tool
 * does not have to pull in the full chain.h/block_index header graph for
 * one constant — the same "re-state so drift trips a test" doctrine
 * lib/test/src/test_self_folded_anchor.c already uses for this same
 * checkpoint (SFA_CHECKPOINT_HEIGHT/SFA_CHECKPOINT_UTXO_COUNT). The
 * hermetic test_utxo_root_ladder test asserts these bytes match the
 * COMPILED checkpoint (get_sha3_utxo_checkpoint()) in the full build —
 * an edit to the real checkpoint that isn't mirrored here trips that
 * test, not a silent drift into the generated ladder table. */
struct gen_checkpoint_anchor {
    int32_t height;
    uint8_t block_hash[32];
    uint8_t sha3_hash[32];
};

static const struct gen_checkpoint_anchor g_checkpoint_anchor = {
    .height = 3056758,
    .block_hash = {
        /* 000002979090fba9da6cdc140d050245c1b637480609510922662407855bd653 */
        0x53, 0xd6, 0x5b, 0x85, 0x07, 0x24, 0x66, 0x22,
        0x09, 0x51, 0x09, 0x06, 0x48, 0x37, 0xb6, 0xc1,
        0x45, 0x02, 0x05, 0x0d, 0x14, 0xdc, 0x6c, 0xda,
        0xa9, 0xfb, 0x90, 0x90, 0x97, 0x02, 0x00, 0x00,
    },
    .sha3_hash = {
        /* 5817f0ec66738db6989cf881cf37b2148d07b978fd69e5a334855b4991ac5f85 */
        0x58, 0x17, 0xf0, 0xec, 0x66, 0x73, 0x8d, 0xb6,
        0x98, 0x9c, 0xf8, 0x81, 0xcf, 0x37, 0xb2, 0x14,
        0x8d, 0x07, 0xb9, 0x78, 0xfd, 0x69, 0xe5, 0xa3,
        0x34, 0x85, 0x5b, 0x49, 0x91, 0xac, 0x5f, 0x85,
    },
};

enum provenance {
    PROV_SINGLE     = 0,
    PROV_DUAL       = 1,
    PROV_CHECKPOINT = 2,
};

struct entry {
    int32_t height;
    uint8_t block_hash[32];
    uint8_t utxo_root[32];
    uint8_t provenance;
};

/* ── sqlite helpers (standalone tool — raw sqlite3_step is sanctioned) ── */

static bool immutable_path_uri(const char *path, char *out, size_t out_cap)
{
    struct stat wal_st;
    char wal[1024];
    int n = snprintf(wal, sizeof(wal), "%s-wal", path ? path : "");
    if (!path || path[0] != '/' || strchr(path, '?') || strchr(path, '#') ||
        strchr(path, '%') || n <= 0 || (size_t)n >= sizeof(wal) ||
        (stat(wal, &wal_st) == 0 && wal_st.st_size > 0))
        return false;
    n = snprintf(out, out_cap, "file:%s?mode=ro&immutable=1", path);
    return n > 0 && (size_t)n < out_cap;
}

static sqlite3 *open_db_ro(const char *path, bool immutable)
{
    sqlite3 *db = NULL;
    /* Not SQLITE_OPEN_URI immutable=1: our caller's contract is that
     * `path` is always a static COPY (never the live datadir), and a
     * plain read-write open lets sqlite merge any -wal frames the copy
     * carried over instead of silently reading a stale checkpoint. */
    char uri[1200];
    const char *locator = path;
    int flags = SQLITE_OPEN_READWRITE;
    if (immutable) {
        if (!immutable_path_uri(path, uri, sizeof(uri))) {
            fprintf(stderr,
                    "[gen_utxo_root_ladder] immutable source requires an "
                    "absolute URI-safe path with no nonempty WAL: %s\n",
                    path ? path : "(null)");
            return NULL;
        }
        locator = uri;
        flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_URI;
    }
    int rc = sqlite3_open_v2(locator, &db, flags, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[gen_utxo_root_ladder] open %s failed: %s\n",
                path, sqlite3_errmsg(db));
        if (db) sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 5000);
    return db;
}

/* ATTACH the sibling kernel-db copy (consensus.db post-flip, progress.kv on
 * a pre-flip datadir) as schema "kdb" onto an already-open node.db
 * connection, so one connection can join `blocks` (node.db) with
 * `progress_meta` (kernel store). Returns false (and logs) on failure —
 * callers treat that as "no boundary-root source available", not fatal. */
static bool attach_kernel_db(sqlite3 *db, const char *path, bool immutable)
{
    if (!path) return false;
    char uri[1200];
    const char *locator = path;
    if (immutable) {
        if (!immutable_path_uri(path, uri, sizeof(uri))) {
            fprintf(stderr,
                    "[gen_utxo_root_ladder] immutable kernel-db source "
                    "requires an absolute URI-safe path with no nonempty "
                    "WAL: %s\n", path);
            return false;
        }
        locator = uri;
    }
    sqlite3_stmt *stmt = NULL;
    bool ok = sqlite3_prepare_v2(db, "ATTACH DATABASE ?1 AS kdb", -1,
                                 &stmt, NULL) == SQLITE_OK &&
              sqlite3_bind_text(stmt, 1, locator, -1, SQLITE_STATIC) ==
                  SQLITE_OK &&
              sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:standalone-dev-tool
    if (!ok) {
        fprintf(stderr, "[gen_utxo_root_ladder] ATTACH %s failed: %s\n",
                path, sqlite3_errmsg(db));
        if (stmt)
            sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

static bool db_max_height(sqlite3 *db, int32_t *out)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT MAX(height) FROM blocks WHERE status>=3",
                           -1, &s, NULL) != SQLITE_OK)
        return false;
    bool ok = false;
    if (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:standalone-dev-tool
        if (sqlite3_column_type(s, 0) != SQLITE_NULL) {
            *out = sqlite3_column_int(s, 0);
            ok = true;
        }
    }
    sqlite3_finalize(s);
    return ok;
}

static bool db_block_hash_at(sqlite3 *db, int32_t height, uint8_t out[32])
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT hash FROM blocks WHERE height=? AND status>=3 LIMIT 1",
            -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(s, 1, height);
    bool ok = false;
    if (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:standalone-dev-tool
        const void *blob = sqlite3_column_blob(s, 0);
        int len = sqlite3_column_bytes(s, 0);
        if (blob && len == 32) {
            memcpy(out, blob, 32);
            ok = true;
        }
    }
    sqlite3_finalize(s);
    return ok;
}

/* `has_kdb` gates whether we query the attached kdb schema at all — a
 * NULL/failed ATTACH means "no boundary-root source", not "not found at
 * this height", so callers can tell the two apart if needed. */
static bool db_boundary_root_at(sqlite3 *db, bool has_kdb, int32_t height,
                                uint8_t out[32])
{
    if (!has_kdb) return false;
    char key[40];
    snprintf(key, sizeof(key), "mmb_utxo_root:%d", (int)height);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT value FROM kdb.progress_meta WHERE key=?",
            -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(s, 1, key, -1, SQLITE_TRANSIENT);
    bool ok = false;
    if (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:standalone-dev-tool
        const void *blob = sqlite3_column_blob(s, 0);
        int len = sqlite3_column_bytes(s, 0);
        if (blob && len == 32) {
            memcpy(out, blob, 32);
            ok = true;
        }
    }
    sqlite3_finalize(s);
    return ok;
}

/* ── hex ─────────────────────────────────────────────────────────── */

static void hex32(const uint8_t h[32], char out[65])
{
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2] = d[h[i] >> 4];
        out[i * 2 + 1] = d[h[i] & 0x0f];
    }
    out[64] = '\0';
}

/* ── CLI ─────────────────────────────────────────────────────────── */

struct cli {
    const char *source_db;          /* node.db copy (required, positional) */
    const char *source_kernel_db;   /* consensus.db (or legacy progress.kv)
                                      * copy — boundary roots */
    const char *second_db;          /* NULL = not given */
    const char *second_kernel_db;   /* NULL = not given */
    const char *leaf_store;         /* NULL = not given */
    int32_t stride;
    int32_t max_height;      /* -1 = auto */
    int32_t dense_height;    /* -1 = auto, -2 = disabled */
    bool immutable_source;   /* forensic no-write open; refuses nonempty WAL */
    const char *out_h;
    const char *out_c;
};

static bool parse_cli(int argc, char **argv, struct cli *c)
{
    c->source_db = NULL;
    c->source_kernel_db = NULL;
    c->second_db = NULL;
    c->second_kernel_db = NULL;
    c->leaf_store = NULL;
    c->stride = DEFAULT_STRIDE;
    c->max_height = -1;
    c->dense_height = -1;
    c->immutable_source = false;
    c->out_h = DEFAULT_OUT_H;
    c->out_c = DEFAULT_OUT_C;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strncmp(a, "--source-kernel-db=", 19) == 0)
            c->source_kernel_db = a + 19;
        else if (strncmp(a, "--source-progress-kv=", 21) == 0)
            c->source_kernel_db = a + 21;  /* alias: pre-flip datadirs */
        else if (strncmp(a, "--second-db=", 12) == 0) c->second_db = a + 12;
        else if (strncmp(a, "--second-kernel-db=", 19) == 0)
            c->second_kernel_db = a + 19;
        else if (strncmp(a, "--second-progress-kv=", 21) == 0)
            c->second_kernel_db = a + 21;  /* alias: pre-flip datadirs */
        else if (strncmp(a, "--leaf-store=", 13) == 0) c->leaf_store = a + 13;
        else if (strncmp(a, "--stride=", 9) == 0) c->stride = atoi(a + 9);
        else if (strncmp(a, "--max-height=", 13) == 0) c->max_height = atoi(a + 13);
        else if (strncmp(a, "--dense-height=", 15) == 0) c->dense_height = atoi(a + 15);
        else if (strcmp(a, "--immutable-source") == 0) c->immutable_source = true;
        else if (strncmp(a, "--out-h=", 8) == 0) c->out_h = a + 8;
        else if (strncmp(a, "--out-c=", 8) == 0) c->out_c = a + 8;
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            printf("Usage: %s <source_node_db_copy> "
                   "--source-kernel-db=PATH "
                   "[--second-db=PATH] [--second-kernel-db=PATH] "
                   "[--leaf-store=PATH] [--stride=N] [--max-height=N] "
                   "[--dense-height=N] [--immutable-source] "
                   "[--out-h=PATH] [--out-c=PATH]\n"
                   "  (--source-progress-kv=/--second-progress-kv= accepted "
                   "as aliases for pre-flip datadirs)\n",
                   argv[0]);
            return false;
        } else if (a[0] == '-') {
            fprintf(stderr, "unknown flag: %s\n", a);
            return false;
        } else if (!c->source_db) {
            c->source_db = a;
        } else {
            fprintf(stderr, "unexpected extra positional arg: %s\n", a);
            return false;
        }
    }
    if (!c->source_db) {
        fprintf(stderr, "missing required <source_node_db_copy> argument\n");
        return false;
    }
    if (!c->source_kernel_db) {
        fprintf(stderr, "missing required --source-kernel-db=PATH "
                        "(boundary UTXO roots live there, not in node.db — "
                        "see lib/storage/src/consensus_db.c)\n");
        return false;
    }
    if (c->stride <= 0 || (c->stride % MMR_COMMITMENT_INTERVAL) != 0) {
        fprintf(stderr, "--stride must be a positive multiple of "
                        "MMR_COMMITMENT_INTERVAL(%d), got %d\n",
                MMR_COMMITMENT_INTERVAL, c->stride);
        return false;
    }
    return true;
}

/* ── Output emitters (mirrors tools/gen_sha3_windows.c discipline) ─── */

static bool emit_header(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return false; }
    fputs(
        "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
        " *\n"
        " * Golden-height UTXO root ladder: cross-checked SHA3 UTXO-set\n"
        " * commitments at fixed stride heights (every UTXO_ROOT_LADDER_STRIDE\n"
        " * blocks, boundary-aligned to MMR_COMMITMENT_INTERVAL) plus the one\n"
        " * zclassicd-verified SHA3 UTXO checkpoint rung (height 3,056,758).\n"
        " *\n"
        " * The blockchain is immutable history: once a stride height's\n"
        " * boundary root is folded from block bodies and cross-checked, it\n"
        " * never changes — this table is a free, permanent reproducibility\n"
        " * anchor a node can verify its own coins_kv against without\n"
        " * re-folding from genesis. See utxo_root_ladder_verify_against_store()\n"
        " * (app/models/src/utxo_root_ladder_verify.c) for the live tripwire:\n"
        " * any mismatch between a locked rung and this node's OWN boundary-root\n"
        " * store is a named divergence at a named height, never a silent stop.\n"
        " *\n"
        " * Generated by tools/gen_utxo_root_ladder. Do not edit by hand. */\n"
        "\n"
        "#ifndef ZCL_CHAIN_UTXO_ROOT_LADDER_H\n"
        "#define ZCL_CHAIN_UTXO_ROOT_LADDER_H\n"
        "\n"
        "#include <stdbool.h>\n"
        "#include <stddef.h>\n"
        "#include <stdint.h>\n"
        "\n"
        "#define UTXO_ROOT_LADDER_STRIDE 100000\n"
        "\n"
        "enum utxo_root_ladder_provenance {\n"
        "    /* One independently-copied boundary-root store recorded this\n"
        "     * value. Not yet cross-checked against a second source. */\n"
        "    UTXO_ROOT_LADDER_SOURCE_SINGLE     = 0,\n"
        "    /* Two independently-folded node.db copies agree bit-for-bit\n"
        "     * on both the block hash and the UTXO root at this height. */\n"
        "    UTXO_ROOT_LADDER_SOURCE_DUAL       = 1,\n"
        "    /* The compiled SHA3 UTXO checkpoint (lib/chain/src/checkpoints.c),\n"
        "     * independently verified bit-for-bit against zclassicd. */\n"
        "    UTXO_ROOT_LADDER_SOURCE_CHECKPOINT = 2,\n"
        "};\n"
        "\n"
        "struct utxo_root_ladder_entry {\n"
        "    int32_t height;\n"
        "    uint8_t block_hash[32];\n"
        "    uint8_t utxo_root[32];\n"
        "    uint8_t provenance;  /* enum utxo_root_ladder_provenance */\n"
        "};\n"
        "\n"
        "extern const struct utxo_root_ladder_entry g_utxo_root_ladder[];\n"
        "extern const size_t g_utxo_root_ladder_count;\n"
        "\n"
        "/* Dense layer (optional; height==-1 means absent): mmb_root(),\n"
        " * recomputed from the raw leaf-hash pipeline up to and including\n"
        " * `g_utxo_root_ladder_dense_height`, locked as one constant. */\n"
        "extern const int32_t g_utxo_root_ladder_dense_height;\n"
        "extern const uint8_t g_utxo_root_ladder_dense_mmb_root[32];\n"
        "\n"
        "/* Returns the entry at exactly `height`, or NULL — not every height\n"
        " * is a rung, only stride multiples of UTXO_ROOT_LADDER_STRIDE plus\n"
        " * the one checkpoint-anchored rung. O(count), count is tiny. */\n"
        "const struct utxo_root_ladder_entry *utxo_root_ladder_lookup(int32_t height);\n"
        "\n"
        "size_t utxo_root_ladder_count(void);\n"
        "\n"
        "#endif /* ZCL_CHAIN_UTXO_ROOT_LADDER_H */\n",
        f);
    fclose(f);
    return true;
}

static void emit_bytes32(FILE *f, const uint8_t b[32])
{
    fputs("{ ", f);
    for (int i = 0; i < 32; i++)
        fprintf(f, "0x%02x%s", b[i], i == 31 ? " " : ", ");
    fputs("}", f);
}

static const char *prov_name(uint8_t p)
{
    switch (p) {
    case PROV_SINGLE:     return "UTXO_ROOT_LADDER_SOURCE_SINGLE";
    case PROV_DUAL:       return "UTXO_ROOT_LADDER_SOURCE_DUAL";
    case PROV_CHECKPOINT: return "UTXO_ROOT_LADDER_SOURCE_CHECKPOINT";
    default:              return "UTXO_ROOT_LADDER_SOURCE_SINGLE";
    }
}

static bool emit_source(const char *path, const struct entry *entries, size_t n,
                        int32_t dense_height, const uint8_t dense_root[32])
{
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return false; }
    fputs(
        "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
        " *\n"
        " * Generated by tools/gen_utxo_root_ladder. Do not edit by hand. */\n"
        "\n"
        "#include \"chain/utxo_root_ladder.h\"\n"
        "\n"
        "#include <string.h>\n"
        "\n"
        "const struct utxo_root_ladder_entry g_utxo_root_ladder[] = {\n",
        f);
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "    { %d, ", entries[i].height);
        emit_bytes32(f, entries[i].block_hash);
        fputs(", ", f);
        emit_bytes32(f, entries[i].utxo_root);
        fprintf(f, ", %s },\n", prov_name(entries[i].provenance));
    }
    fputs("};\n\n", f);
    fprintf(f, "const size_t g_utxo_root_ladder_count = %zu;\n\n", n);
    fprintf(f, "const int32_t g_utxo_root_ladder_dense_height = %d;\n",
            (int)dense_height);
    fputs("const uint8_t g_utxo_root_ladder_dense_mmb_root[32] = ", f);
    emit_bytes32(f, dense_root);
    fputs(";\n\n", f);
    fputs(
        "const struct utxo_root_ladder_entry *utxo_root_ladder_lookup(int32_t height)\n"
        "{\n"
        "    for (size_t i = 0; i < g_utxo_root_ladder_count; i++) {\n"
        "        if (g_utxo_root_ladder[i].height == height)\n"
        "            return &g_utxo_root_ladder[i];\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "\n"
        "size_t utxo_root_ladder_count(void)\n"
        "{\n"
        "    return g_utxo_root_ladder_count;\n"
        "}\n",
        f);
    fclose(f);
    return true;
}

/* ── Dense-layer: recompute mmb_root() from mmb_leaves.bin ─────────── */

static bool compute_dense_mmb_root(const char *leaf_store_path,
                                   int32_t requested_height,
                                   int32_t max_stride_height,
                                   int32_t *out_height, uint8_t out_root[32])
{
    *out_height = -1;
    memset(out_root, 0, 32);
    if (!leaf_store_path) return true;  /* dense layer simply absent */

    int fd = open(leaf_store_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[gen_utxo_root_ladder] open leaf-store %s failed: %s\n",
                leaf_store_path, strerror(errno));
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0 || (st.st_size % 32) != 0) {
        fprintf(stderr, "[gen_utxo_root_ladder] leaf-store %s: bad size %lld\n",
                leaf_store_path, (long long)st.st_size);
        close(fd);
        return false;
    }
    uint64_t num_leaves = (uint64_t)st.st_size / 32;

    int32_t dense_h = requested_height;
    if (dense_h < 0) {
        /* Auto: the largest stride-aligned height we can fully cover. */
        dense_h = max_stride_height;
        while (dense_h >= 0 && (uint64_t)dense_h >= num_leaves)
            dense_h -= DEFAULT_STRIDE;
    }
    if (dense_h < 0 || (uint64_t)dense_h >= num_leaves) {
        fprintf(stderr, "[gen_utxo_root_ladder] leaf-store %s has %llu leaves, "
                        "cannot cover requested dense height %d\n",
                leaf_store_path, (unsigned long long)num_leaves, requested_height);
        close(fd);
        return false;
    }

    uint8_t *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "[gen_utxo_root_ladder] mmap leaf-store failed: %s\n",
                strerror(errno));
        close(fd);
        return false;
    }

    struct mmb m;
    mmb_init(&m);
    for (int64_t i = 0; i <= dense_h; i++) {
        if (mmb_append_hash(&m, map + (size_t)i * 32) < 0) {
            fprintf(stderr, "[gen_utxo_root_ladder] mmb_append_hash failed at "
                            "leaf %lld\n", (long long)i);
            munmap(map, (size_t)st.st_size);
            close(fd);
            return false;
        }
    }
    mmb_root(&m, out_root);
    *out_height = dense_h;

    munmap(map, (size_t)st.st_size);
    close(fd);
    return true;
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    struct cli c;
    if (!parse_cli(argc, argv, &c)) return 1;

    sqlite3 *src = open_db_ro(c.source_db, c.immutable_source);
    if (!src) return 1;
    bool src_has_kdb = attach_kernel_db(
        src, c.source_kernel_db, c.immutable_source);
    if (!src_has_kdb) {
        fprintf(stderr, "[gen_utxo_root_ladder] cannot attach "
                        "--source-kernel-db=%s — stride rungs will all be "
                        "skipped (only the checkpoint rung can be emitted)\n",
                c.source_kernel_db);
    }

    sqlite3 *snd = NULL;
    bool snd_has_kdb = false;
    if (c.second_db) {
        snd = open_db_ro(c.second_db, c.immutable_source);
        if (!snd) { sqlite3_close(src); return 1; }
        snd_has_kdb = attach_kernel_db(
            snd, c.second_kernel_db, c.immutable_source);
    }

    int32_t src_max = -1;
    if (!db_max_height(src, &src_max)) {
        fprintf(stderr, "[gen_utxo_root_ladder] source db has no best-chain "
                        "blocks (blocks.status>=3)\n");
        sqlite3_close(src);
        if (snd) sqlite3_close(snd);
        return 1;
    }
    int32_t max_h = c.max_height >= 0 ? c.max_height : src_max;
    if (max_h > src_max) max_h = src_max;
    if (snd) {
        int32_t snd_max = -1;
        db_max_height(snd, &snd_max);
        printf("[gen_utxo_root_ladder] second-db max_height=%d\n", snd_max);
    }

    printf("[gen_utxo_root_ladder] source=%s max_height=%d stride=%d%s\n",
           c.source_db, max_h, c.stride, snd ? " (dual-source)" : "");

    struct entry entries[MAX_ENTRIES];
    size_t n = 0;
    int divergences = 0;
    int32_t last_stride_height_recorded = -1;

    for (int32_t h = 0; h <= max_h; h += c.stride) {
        uint8_t bh[32], ur[32];
        if (!db_block_hash_at(src, h, bh)) {
            printf("[gen_utxo_root_ladder] h=%d: no best-chain block hash in "
                   "source — skipping rung\n", h);
            continue;
        }
        if (!db_boundary_root_at(src, src_has_kdb, h, ur)) {
            printf("[gen_utxo_root_ladder] h=%d: no boundary utxo_root recorded "
                   "in source (coins_kv_boundary_root_set never ran here) — "
                   "skipping rung\n", h);
            continue;
        }

        uint8_t provenance = PROV_SINGLE;
        if (snd) {
            uint8_t bh2[32], ur2[32];
            bool have2 = db_block_hash_at(snd, h, bh2) &&
                        db_boundary_root_at(snd, snd_has_kdb, h, ur2);
            if (!have2) {
                printf("[gen_utxo_root_ladder] h=%d: second-db has no data yet "
                       "(still folding) — single-source rung\n", h);
            } else if (memcmp(bh, bh2, 32) != 0) {
                char hx1[65], hx2[65];
                hex32(bh, hx1); hex32(bh2, hx2);
                fprintf(stderr, "[gen_utxo_root_ladder] DIVERGENCE h=%d: "
                                "block_hash source=%s second=%s (DIFFERENT CHAINS)\n",
                        h, hx1, hx2);
                divergences++;
            } else if (memcmp(ur, ur2, 32) != 0) {
                char hx1[65], hx2[65];
                hex32(ur, hx1); hex32(ur2, hx2);
                fprintf(stderr, "[gen_utxo_root_ladder] DIVERGENCE h=%d: "
                                "SAME block_hash, utxo_root source=%s second=%s "
                                "(state-wrong-coin class)\n",
                        h, hx1, hx2);
                divergences++;
            } else {
                provenance = PROV_DUAL;
                printf("[gen_utxo_root_ladder] h=%d: DUAL-SOURCE confirmed\n", h);
            }
        }

        if (n >= MAX_ENTRIES) {
            fprintf(stderr, "[gen_utxo_root_ladder] too many rungs (cap=%d)\n",
                    MAX_ENTRIES);
            break;
        }
        entries[n].height = h;
        memcpy(entries[n].block_hash, bh, 32);
        memcpy(entries[n].utxo_root, ur, 32);
        entries[n].provenance = provenance;
        n++;
        last_stride_height_recorded = h;
    }

    /* Checkpoint rung: the one zclassicd-verified anchor. Always included
     * (it does not depend on coins_kv boundary roots at all — it is the
     * compiled, independently-verified constant), with the cheap available
     * cross-check: does SOURCE's own blocks table agree on the block hash
     * at that exact height? */
    {
        const struct gen_checkpoint_anchor *cp = &g_checkpoint_anchor;
        uint8_t bh[32];
        if (db_block_hash_at(src, cp->height, bh)) {
            if (memcmp(bh, cp->block_hash, 32) != 0) {
                char hx1[65], hx2[65];
                hex32(bh, hx1); hex32(cp->block_hash, hx2);
                fprintf(stderr, "[gen_utxo_root_ladder] DIVERGENCE h=%d "
                                "(zclassicd-verified checkpoint): source "
                                "block_hash=%s checkpoint block_hash=%s\n",
                        cp->height, hx1, hx2);
                divergences++;
            } else {
                printf("[gen_utxo_root_ladder] h=%d: checkpoint block_hash "
                       "confirmed against source db\n", cp->height);
            }
        } else {
            printf("[gen_utxo_root_ladder] h=%d: source db has no block at the "
                   "checkpoint height (not reached) — checkpoint rung emitted "
                   "unverified-against-source\n", cp->height);
        }

        if (n >= MAX_ENTRIES) {
            fprintf(stderr, "[gen_utxo_root_ladder] no room for checkpoint rung\n");
        } else {
            /* Insert in height-sorted position. */
            size_t pos = n;
            for (size_t i = 0; i < n; i++) {
                if (entries[i].height > cp->height) { pos = i; break; }
            }
            memmove(&entries[pos + 1], &entries[pos],
                   (n - pos) * sizeof(entries[0]));
            entries[pos].height = cp->height;
            memcpy(entries[pos].block_hash, cp->block_hash, 32);
            memcpy(entries[pos].utxo_root, cp->sha3_hash, 32);
            entries[pos].provenance = PROV_CHECKPOINT;
            n++;
        }
    }

    if (divergences > 0) {
        fprintf(stderr, "[gen_utxo_root_ladder] %d divergence(s) found — "
                        "refusing to emit a locked table. Investigate before "
                        "re-running.\n", divergences);
        sqlite3_close(src);
        if (snd) sqlite3_close(snd);
        return 1;
    }

    int32_t dense_height = -1;
    uint8_t dense_root[32] = {0};
    if (c.leaf_store) {
        if (!compute_dense_mmb_root(c.leaf_store, c.dense_height,
                                    last_stride_height_recorded,
                                    &dense_height, dense_root)) {
            fprintf(stderr, "[gen_utxo_root_ladder] dense-layer computation "
                            "failed — emitting table WITHOUT the dense anchor\n");
            dense_height = -1;
            memset(dense_root, 0, 32);
        } else if (dense_height >= 0) {
            char hx[65];
            hex32(dense_root, hx);
            printf("[gen_utxo_root_ladder] dense mmb_root @ h=%d: %s\n",
                   dense_height, hx);
        }
    }

    sqlite3_close(src);
    if (snd) sqlite3_close(snd);

    if (!emit_header(c.out_h)) return 1;
    if (!emit_source(c.out_c, entries, n, dense_height, dense_root)) return 1;

    printf("[gen_utxo_root_ladder] wrote %s and %s (%zu rungs, dense=%s)\n",
           c.out_h, c.out_c, n, dense_height >= 0 ? "yes" : "no");
    return 0;
}
