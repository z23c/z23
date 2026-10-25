/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * verify_anchor_completeness — cross-checks a zclassicd chainstate LevelDB
 * against a z23 kernel store (consensus.db, or the legacy progress.kv
 * on a pre-flip datadir) to answer one question: did the shielded history
 * importer (shielded_history_import_service.c) capture every anchor and
 * nullifier its SOURCE chainstate held?
 *
 * Deliberately independent of chainstate_legacy_reader.c: this walks the raw
 * LevelDB keyspace directly via the vendored leveldb C API and counts keys by
 * first-byte prefix. LevelDB keys in the zcashd/zclassicd dbwrapper scheme are
 * never XOR-obfuscated — only values are (see the 'obfuscate_key' record) —
 * so a raw prefix-byte key count needs no deobfuscation and is a correct,
 * minimal ground truth that does not share any code path with the importer.
 *
 *   'Z' = DB_SAPLING_ANCHOR      'A' = DB_SPROUT_ANCHOR
 *   'S' = DB_SAPLING_NULLIFIER   's' = DB_NULLIFIER (sprout)
 *
 * The chainstate LevelDB and the kernel store are both opened read-only —
 * this never writes to either. Point this at a COPY of zclassicd's
 * chainstate (zclassicd holds an exclusive lock on the live one) and the
 * consensus.db (or, for a pre-flip datadir, progress.kv) belonging to a
 * node that ran the historical import.
 *
 * A raw-key deficit vs. the imported count is EXPECTED and not a bug when it
 * traces to real chain growth after the importer's source snapshot was taken
 * (see the note this tool prints about best_block height vs. current
 * chainstate height) — it only indicates a reader defect if the SOURCE
 * chainstate (the exact copy the import ran against) has keys the importer's
 * own reported count does not account for.
 *
 * Usage: verify_anchor_completeness <chainstate_dir> <kernel_store_path>
 */
#include <leveldb/c.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct raw_counts {
    long long z_sapling_anchor;
    long long a_sprout_anchor;
    long long s_sapling_nullifier;
    long long s_sprout_nullifier;
    long long bad_key_len; /* prefix-matched key whose length != 33 */
};

static void count_key_by_prefix(const char *k, size_t klen, struct raw_counts *out)
{
    if (klen >= 1) {
        switch ((unsigned char)k[0]) {
        case 'Z': out->z_sapling_anchor++;    if (klen != 33) out->bad_key_len++; break;
        case 'A': out->a_sprout_anchor++;     if (klen != 33) out->bad_key_len++; break;
        case 'S': out->s_sapling_nullifier++; if (klen != 33) out->bad_key_len++; break;
        case 's': out->s_sprout_nullifier++;  if (klen != 33) out->bad_key_len++; break;
        default: break;
        }
    }
}

static int count_chainstate(const char *chainstate_dir, struct raw_counts *out)
{
    memset(out, 0, sizeof(*out));

    leveldb_options_t *opts = leveldb_options_create();
    leveldb_options_set_create_if_missing(opts, 0);
    leveldb_options_set_paranoid_checks(opts, 1);
    char *err = NULL;
    leveldb_t *db = leveldb_open(opts, chainstate_dir, &err);
    if (err || !db) {
        fprintf(stderr, "chainstate open failed: %s\n", err ? err : "(unknown)");
        if (err) leveldb_free(err);
        leveldb_options_destroy(opts);
        return -1;
    }

    leveldb_readoptions_t *ropts = leveldb_readoptions_create();
    leveldb_readoptions_set_verify_checksums(ropts, 1);
    leveldb_readoptions_set_fill_cache(ropts, 0);
    leveldb_iterator_t *it = leveldb_create_iterator(db, ropts);

    leveldb_iter_seek_to_first(it);
    while (leveldb_iter_valid(it)) {
        size_t klen = 0;
        const char *k = leveldb_iter_key(it, &klen);
        count_key_by_prefix(k, klen, out);
        leveldb_iter_next(it);
    }

    char *iter_err = NULL;
    leveldb_iter_get_error(it, &iter_err);
    int rc = 0;
    if (iter_err) {
        fprintf(stderr, "ITERATOR ERROR (torn/corrupt SST?): %s\n", iter_err);
        leveldb_free(iter_err);
        rc = -1;
    }

    leveldb_iter_destroy(it);
    leveldb_readoptions_destroy(ropts);
    leveldb_options_destroy(opts);
    leveldb_close(db);
    return rc;
}

struct imported_counts {
    long long sapling_anchors;
    long long sprout_anchors;
    long long sapling_nullifiers; /* pool=1 */
    long long sprout_nullifiers;  /* pool=0 */
    char provenance[512];
    int have_provenance;
};

static long long sql_count1(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *s = NULL;
    long long v = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:diagnostic-verify-tool
        v = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return v;
}

static int count_kernel_store(const char *kernel_store_path, struct imported_counts *out)
{
    memset(out, 0, sizeof(*out));
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(kernel_store_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        fprintf(stderr, "kernel store open failed: %s\n", sqlite3_errmsg(db));
        if (db) sqlite3_close(db);
        return -1;
    }

    out->sapling_anchors    = sql_count1(db, "SELECT count(*) FROM sapling_anchors");
    out->sprout_anchors     = sql_count1(db, "SELECT count(*) FROM sprout_anchors");
    out->sapling_nullifiers = sql_count1(db, "SELECT count(*) FROM nullifiers WHERE pool=1");
    out->sprout_nullifiers  = sql_count1(db, "SELECT count(*) FROM nullifiers WHERE pool=0");

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT value FROM progress_meta WHERE key='shielded_import.provenance'",
            -1, &s, NULL) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:diagnostic-verify-tool
            const unsigned char *v = sqlite3_column_text(s, 0);
            if (v) {
                snprintf(out->provenance, sizeof(out->provenance), "%s", (const char *)v);
                out->have_provenance = 1;
            }
        }
        sqlite3_finalize(s);
    }

    sqlite3_close(db);
    return 0;
}

static void report_line(const char *label, long long chainstate, long long imported)
{
    long long delta = chainstate - imported;
    printf("  %-24s chainstate=%-10lld imported=%-10lld delta=%+lld%s\n",
           label, chainstate, imported, delta,
           delta == 0 ? "  (exact match)" : "");
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <chainstate_dir> <kernel_store_path>\n", argv[0]);
        return 2;
    }
    const char *chainstate_dir = argv[1];
    const char *kernel_store_path = argv[2];

    struct raw_counts rc;
    if (count_chainstate(chainstate_dir, &rc) != 0)
        return 1;

    struct imported_counts ic;
    if (count_kernel_store(kernel_store_path, &ic) != 0)
        return 1;

    printf("chainstate: %s\n", chainstate_dir);
    printf("kernel store: %s\n", kernel_store_path);
    if (ic.have_provenance)
        printf("import provenance: %s\n", ic.provenance);
    printf("\n");

    if (rc.bad_key_len)
        printf("WARNING: %lld anchor/nullifier-prefixed key(s) had length != 33\n",
               rc.bad_key_len);

    report_line("sapling anchors (Z)", rc.z_sapling_anchor, ic.sapling_anchors);
    report_line("sprout anchors (A)", rc.a_sprout_anchor, ic.sprout_anchors);
    report_line("sapling nullifiers (S)", rc.s_sapling_nullifier, ic.sapling_nullifiers);
    report_line("sprout nullifiers (s)", rc.s_sprout_nullifier, ic.sprout_nullifiers);

    printf("\n");
    if (rc.z_sapling_anchor < ic.sapling_anchors ||
        rc.a_sprout_anchor < ic.sprout_anchors ||
        rc.s_sapling_nullifier < ic.sapling_nullifiers ||
        rc.s_sprout_nullifier < ic.sprout_nullifiers) {
        printf("VERDICT: IMPOSSIBLE — imported count exceeds this chainstate's raw "
               "key count for at least one pool. Either the kernel store holds rows from a "
               "different/larger chainstate, or the chainstate copy is torn.\n");
        return 1;
    }
    if (rc.z_sapling_anchor == ic.sapling_anchors &&
        rc.a_sprout_anchor == ic.sprout_anchors &&
        rc.s_sapling_nullifier == ic.sapling_nullifiers &&
        rc.s_sprout_nullifier == ic.sprout_nullifiers) {
        printf("VERDICT: COMPLETE — every anchor/nullifier key in this chainstate copy "
               "is accounted for in the kernel store.\n");
        return 0;
    }
    printf("VERDICT: DEFICIT — this chainstate copy has more anchor/nullifier keys than "
           "the kernel store reports imported. Confirm whether this chainstate is NEWER than "
           "the import's own source (compare its 'B' best-block height against the "
           "provenance line's best_block/tip_h above) before treating this as a reader "
           "bug — chain growth after the import's source snapshot produces exactly this "
           "shape of deficit (a Sapling-only gap; the long-dead Sprout pool stays exact).\n");
    return 0;
}
