/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for ZID (sovereign identity layer Phase 1) — ed25519 keypair/sign
 * against the RFC 8032 §7.1 vectors, and the zid document codec:
 * encode/decode round-trip, tamper rejection, expiry, blinded keys, and
 * the monotonic-seq supersede rule. */

#include "test/test_core.h"
#include "zid/zid.h"
#include "zid/zid_anchor.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "models/database.h"
#include "models/zid_domain.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "json/json.h"
#include <stdlib.h>
#include "script/standard.h"
#include "base/log_level.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "platform/clock.h"
#include <string.h>

/* contexts/wallet/modules/zid sits BELOW core/modules/script in engine/composition/lib_module_order.def, so
 * zid_anchor.h keeps its own copy of the standard-relay ceiling. lib/test is
 * above both and can see each definition, so this is where the copy is
 * pinned: if MAX_OP_RETURN_RELAY ever moves, this fails to COMPILE rather
 * than letting the ZID overlay silently emit a non-relayable script. */
_Static_assert(ZID_ANCHOR_RELAY_MAX == MAX_OP_RETURN_RELAY,
               "zid_anchor relay cap must track script/standard.h");
_Static_assert(ZID_ANCHOR_SCRIPT_MAX <= ZID_ANCHOR_RELAY_MAX,
               "the largest ZID anchor must fit the relay cap");

static size_t hex_to_bytes(const char *hex, uint8_t *out, size_t out_max)
{
    size_t n = strlen(hex) / 2;
    if (n > out_max) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return n;
}

/* ── ZID on-chain anchor helpers ───────────────────────────────────
 *
 * Hand-assemble a ZID anchor OP_RETURN so each negative can be malformed in
 * exactly ONE way (wrong lokad / wrong version / wrong command byte / wrong
 * key length) instead of relying on byte-poking a built script. Every push
 * in this grammar is short-form (len <= 0x4b), so the 1-byte prefix is
 * always correct. */
static size_t zid_anchor_push(uint8_t *out, size_t off,
                              const uint8_t *d, size_t n)
{
    out[off++] = (uint8_t)n;
    memcpy(out + off, d, n);
    return off + n;
}

static size_t zid_anchor_handmade(uint8_t *out, const char lokad[4],
                                  uint8_t version, uint8_t command,
                                  const uint8_t *key, size_t key_len)
{
    size_t off = 0;
    out[off++] = 0x6a;                                     /* OP_RETURN */
    off = zid_anchor_push(out, off, (const uint8_t *)lokad, 4);
    off = zid_anchor_push(out, off, &version, 1);
    off = zid_anchor_push(out, off, &command, 1);
    off = zid_anchor_push(out, off, key, key_len);
    return off;
}

/* Byte-exact comparison against a FROZEN golden vector. These vectors are
 * the wire contract: changing one is a protocol change, not a test edit. */
static bool zid_anchor_golden_matches(const uint8_t *script, size_t len,
                                      const char *want_hex)
{
    uint8_t want[ZID_ANCHOR_SCRIPT_MAX];
    size_t want_len = hex_to_bytes(want_hex, want, sizeof(want));
    return want_len > 0 && want_len == len &&
           memcmp(script, want, want_len) == 0;
}

/* RFC 8032 §7.1 TEST 1 / TEST 2: derive the keypair from the seed, sign
 * the message, and require byte-exact equality with the published pk and
 * sig, plus acceptance by ed25519_verify. */
static int test_rfc8032_vector(const char *label, const char *seed_hex,
                               const char *pk_hex, const uint8_t *msg,
                               size_t msg_len, const char *sig_hex)
{
    int failures = 0;
    uint8_t seed[32], want_pk[32], want_sig[64];
    hex_to_bytes(seed_hex, seed, sizeof(seed));
    hex_to_bytes(pk_hex, want_pk, sizeof(want_pk));
    hex_to_bytes(sig_hex, want_sig, sizeof(want_sig));

    uint8_t pk[32], sk[32];
    ed25519_keypair(pk, sk, seed);

    printf("ed25519 %s: keypair pk matches RFC 8032... ", label);
    if (memcmp(pk, want_pk, 32) == 0 && memcmp(sk, seed, 32) == 0)
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    uint8_t sig[64];
    ed25519_sign(sig, msg, msg_len, sk, pk);

    printf("ed25519 %s: sign matches RFC 8032... ", label);
    if (memcmp(sig, want_sig, 64) == 0)
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("ed25519 %s: published vector verifies... ", label);
    if (ed25519_verify(want_sig, msg, msg_len, want_pk))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("ed25519 %s: own signature verifies... ", label);
    if (ed25519_verify(sig, msg, msg_len, pk))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    return failures;
}

/* ── Durable anchor domains (models/zid_domain.h, schema v38) ───────
 *
 * The store exists so a batch proof cannot silently change meaning: the
 * leaf set that produced a root is on disk next to it, instead of being
 * re-derived by scanning a directory that may have changed. These cases
 * pin exactly that contract — atomic leaf replacement, a root that is a
 * pure function of the stored leaf set, a proof built from the table that
 * verifies with zid_tree_verify, and two domains that never touch each
 * other's rows. */

struct zd_fixture {
    uint8_t digests[4][32];
    char labels[4][ZID_DOMAIN_LABEL_MAX + 1];
    size_t n;
};

static int zd_digest_cmp(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

/* Sign n release docs for `pkg`, digest their canonical wire bytes, and
 * return the digests in the SAME canonical byte-sorted order the anchor
 * path uses. Labels are attached after the sort (label lookup is by
 * digest, so it must survive re-ordering). */
static void zd_build_fixture(struct zd_fixture *f, const char *pkg, size_t n,
                             const uint8_t seed[32], uint64_t now)
{
    memset(f, 0, sizeof(*f));
    f->n = n;
    for (size_t i = 0; i < n; i++) {
        struct zid_release r;
        memset(&r, 0, sizeof(r));
        snprintf(r.name, sizeof(r.name), "%s", pkg);
        snprintf(r.version, sizeof(r.version), "0.%zu", i);
        memset(r.manifest_root, (int)(0x40 + i), 32);
        struct zid_doc d;
        zid_release_sign(&d, &r, 1, now + 3600, seed);
        uint8_t w[ZID_DOC_MAX];
        size_t wlen = zid_doc_encode(w, sizeof(w), &d);
        zid_record_digest(f->digests[i], w, wlen);
    }
    qsort(f->digests, n, 32, zd_digest_cmp);
    for (size_t i = 0; i < n; i++)
        snprintf(f->labels[i], sizeof(f->labels[i]), "%s@leaf%zu", pkg, i);
}

static void zd_fill_leaves(struct zid_domain_leaf *out,
                           const struct zd_fixture *f, const char *domain,
                           size_t n)
{
    for (size_t i = 0; i < n; i++) {
        memset(&out[i], 0, sizeof(out[i]));
        snprintf(out[i].domain_name, sizeof(out[i].domain_name), "%s", domain);
        out[i].leaf_index = (int64_t)i;
        memcpy(out[i].record_digest, f->digests[i], 32);
        snprintf(out[i].label, sizeof(out[i].label), "%s", f->labels[i]);
    }
}

/* Fill the frame a sibling call will reuse with 0xCD — what an uninitialised
 * `struct json_value` local looks like when json_free() walks it: type is not
 * JSON_STR (no free of val.s) but num_children/children are both huge, so the
 * child walk dereferences 0xCDCD... and faults. volatile + a byte loop so no
 * optimiser can drop it. NOT called by production code. */
static void zd_poison_frame(void)
{
    volatile unsigned char pad[16384];
    for (size_t i = 0; i < sizeof(pad); i++)
        pad[i] = 0xCD;
}

static int test_zid_domain_store(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));

    printf("\n=== ZID anchor domain store ===\n");

    printf("zid_domain: open in-memory node.db at schema v%d... ",
           NODE_DB_MAX_SCHEMA);
    if (node_db_open(&ndb, ":memory:") && ndb.open &&
        node_db_schema_version(&ndb) == NODE_DB_MAX_SCHEMA)
        printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    uint8_t seed[32];
    memset(seed, 0x5a, sizeof(seed));
    uint64_t now = 1750000000ull;

    struct zd_fixture code3;
    zd_build_fixture(&code3, "demo", 3, seed, now);
    struct zid_domain_leaf leaves[4];
    zd_fill_leaves(leaves, &code3, "zcode", 3);

    uint8_t root3[32];
    zid_tree_root_from_digests((const uint8_t (*)[32])code3.digests, 3, root3);

    printf("zid_domain: replace_leaves stores the batch + its root... ");
    {
        struct zid_domain d;
        bool ok = zid_domain_replace_leaves(&ndb, "zcode", leaves, 3, root3,
                                            NULL, now) &&
                  zid_domain_get(&ndb, "zcode", &d) &&
                  d.num_leaves == 3 &&
                  memcmp(d.root, root3, 32) == 0 &&
                  !d.anchored && d.anchored_height == -1 &&
                  zid_domain_leaf_count(&ndb, "zcode") == 3;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("zid_domain: the same leaf set always folds to the same root... ");
    {
        /* Re-store the identical set, then re-fold from what the TABLE
         * holds: a root read back out must be a pure function of the
         * stored leaves, never of write order or of the releases dir. */
        struct zid_domain_leaf again[4];
        zd_fill_leaves(again, &code3, "zcode", 3);
        struct zid_domain_leaf read_back[4];
        uint8_t from_table[32];
        struct zid_domain d;
        bool ok = zid_domain_replace_leaves(&ndb, "zcode", again, 3, root3,
                                            NULL, now + 1) &&
                  zid_domain_get(&ndb, "zcode", &d) &&
                  memcmp(d.root, root3, 32) == 0 &&
                  zid_domain_leaves(&ndb, "zcode", read_back, 4) == 3;
        if (ok) {
            uint8_t digests[4][32];
            for (int i = 0; i < 3; i++) {
                if (read_back[i].leaf_index != i) ok = false;
                memcpy(digests[i], read_back[i].record_digest, 32);
            }
            ok = ok &&
                 zid_tree_root_from_digests((const uint8_t (*)[32])digests, 3,
                                            from_table) &&
                 memcmp(from_table, root3, 32) == 0;
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("zid_domain: a proof built from the table verifies... ");
    {
        struct zid_domain_leaf read_back[4];
        struct zid_domain d;
        int64_t idx = -1;
        bool ok = zid_domain_get(&ndb, "zcode", &d) &&
                  zid_domain_leaves(&ndb, "zcode", read_back, 4) == 3 &&
                  zid_domain_leaf_index_by_digest(&ndb, "zcode",
                                                  code3.digests[1], &idx) &&
                  idx == 1;
        if (ok) {
            uint8_t digests[4][32];
            for (int i = 0; i < 3; i++)
                memcpy(digests[i], read_back[i].record_digest, 32);
            uint8_t proof[ZID_TREE_MAX_PEAKS][32], pr[32];
            uint32_t plen = 0;
            ok = zid_tree_prove_from_leaves((const uint8_t (*)[32])digests, 3,
                                            (uint64_t)idx, proof, &plen, pr) &&
                 memcmp(pr, d.root, 32) == 0 &&
                 zid_tree_verify(d.root, digests[idx], (uint64_t)idx, 3,
                                 proof, plen) &&
                 /* and the same proof must NOT verify a different leaf */
                 !zid_tree_verify(d.root, digests[0], (uint64_t)idx, 3,
                                  proof, plen);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("zid_domain: set_anchor records txid+height; a same-root "
           "re-fold keeps it... ");
    {
        uint8_t txid[32];
        memset(txid, 0xC7, sizeof(txid));
        struct zid_domain_leaf again[4];
        zd_fill_leaves(again, &code3, "zcode", 3);
        struct zid_domain d;
        bool ok = zid_domain_set_anchor(&ndb, "zcode", txid, 3056758) &&
                  zid_domain_get(&ndb, "zcode", &d) && d.anchored &&
                  memcmp(d.anchored_txid, txid, 32) == 0 &&
                  d.anchored_height == 3056758 &&
                  zid_domain_replace_leaves(&ndb, "zcode", again, 3, root3,
                                            NULL, now + 2) &&
                  zid_domain_get(&ndb, "zcode", &d) && d.anchored &&
                  d.anchored_height == 3056758;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("zid_domain: leaf replacement is atomic — a shorter set leaves "
           "no stale leaf, and the anchor is cleared... ");
    {
        /* Two leaves instead of three: the dropped leaf must be GONE, the
         * root must be the two-leaf root, and the anchor must not survive
         * a meaning change. */
        struct zid_domain_leaf shorter[4];
        zd_fill_leaves(shorter, &code3, "zcode", 2);
        uint8_t root2[32];
        zid_tree_root_from_digests((const uint8_t (*)[32])code3.digests, 2,
                                   root2);
        struct zid_domain d;
        int64_t gone = -1;
        bool ok = zid_domain_replace_leaves(&ndb, "zcode", shorter, 2, root2,
                                            NULL, now + 3) &&
                  zid_domain_get(&ndb, "zcode", &d) &&
                  d.num_leaves == 2 &&
                  memcmp(d.root, root2, 32) == 0 &&
                  zid_domain_leaf_count(&ndb, "zcode") == 2 &&
                  !zid_domain_leaf_index_by_digest(&ndb, "zcode",
                                                   code3.digests[2], &gone) &&
                  !d.anchored && d.anchored_height == -1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        /* Restore the three-leaf batch for the coexistence case below. */
        struct zid_domain_leaf full[4];
        zd_fill_leaves(full, &code3, "zcode", 3);
        zid_domain_replace_leaves(&ndb, "zcode", full, 3, root3, NULL, now + 4);
    }

    printf("zid_domain: two domains coexist without interfering... ");
    {
        struct zd_fixture desc;
        zd_build_fixture(&desc, "zdesc", 4, seed, now + 99);
        struct zid_domain_leaf dl[4];
        zd_fill_leaves(dl, &desc, "zdesc", 4);
        uint8_t droot[32];
        zid_tree_root_from_digests((const uint8_t (*)[32])desc.digests, 4,
                                   droot);
        uint8_t txid[32];
        memset(txid, 0xD5, sizeof(txid));

        struct zid_domain a, b;
        int64_t idx = -1;
        bool ok = zid_domain_replace_leaves(&ndb, "zdesc", dl, 4, droot, NULL,
                                            now + 5) &&
                  zid_domain_set_anchor(&ndb, "zdesc", txid, 42) &&
                  /* zcode is untouched by every zdesc write */
                  zid_domain_get(&ndb, "zcode", &a) && a.num_leaves == 3 &&
                  memcmp(a.root, root3, 32) == 0 && !a.anchored &&
                  zid_domain_leaf_count(&ndb, "zcode") == 3 &&
                  /* zdesc carries its own root, leaves and anchor */
                  zid_domain_get(&ndb, "zdesc", &b) && b.num_leaves == 4 &&
                  memcmp(b.root, droot, 32) == 0 && b.anchored &&
                  b.anchored_height == 42 &&
                  zid_domain_leaf_count(&ndb, "zdesc") == 4 &&
                  /* digest lookup is scoped to its domain */
                  zid_domain_leaf_index_by_digest(&ndb, "zdesc",
                                                  desc.digests[3], &idx) &&
                  idx == 3 &&
                  !zid_domain_leaf_index_by_digest(&ndb, "zcode",
                                                   desc.digests[3], &idx) &&
                  zid_domain_count(&ndb) == 2;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("zid_domain: an unknown domain cannot be anchored, and a bad "
           "name is refused... ");
    {
        uint8_t txid[32];
        memset(txid, 0x11, sizeof(txid));
        struct zid_domain bad;
        memset(&bad, 0, sizeof(bad));
        snprintf(bad.domain_name, sizeof(bad.domain_name), "Not A Domain");
        memset(bad.root, 0x22, 32);
        bad.updated_at = (int64_t)now;
        struct zid_domain probe;
        bool ok = !zid_domain_set_anchor(&ndb, "nosuch", txid, 7) &&
                  !db_zid_domain_save(&ndb, &bad) &&
                  !zid_domain_get(&ndb, "Not A Domain", &probe) &&
                  zid_domain_count(&ndb) == 2;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* zid_domain_dump_state_json ran json_set_array()/json_set_object() on
     * uninitialised stack locals. Those setters json_free() the value first
     * (json.h lifecycle note), so the free walked whatever the previous frame
     * left there. On the C3 stopwatch's serving fixture peer that was a
     * SIGSEGV every ~15 minutes, inside stopwatch runs, killing the only peer
     * the syncing client had:
     *   json_free+0x43 <- zid_domain_dump_state_json+0x1b9 <- debug_bundle_write
     * Poison the frame the dumper is about to occupy, then call it for real. */
    printf("zid_domain: dump_state_json survives a poisoned caller frame... ");
    {
        struct db_service dbsvc;
        struct app_runtime_context runtime;
        memset(&runtime, 0, sizeof(runtime));
        db_service_init(&dbsvc);
        bool wired = db_service_attach(&dbsvc, &ndb) &&
                     db_service_start(&dbsvc);
        if (wired) {
            runtime.db_service = &dbsvc;
            app_runtime_set_current(&runtime);
        }
        zd_poison_frame();
        struct json_value out = {0};
        json_set_object(&out);
        bool ok = wired && zid_domain_dump_state_json(&out, NULL) &&
                  json_get(&out, "roster") != NULL;
        json_free(&out);
        /* Keyed form too: it has its own uninitialised local. */
        zd_poison_frame();
        struct json_value one = {0};
        json_set_object(&one);
        ok = ok && zid_domain_dump_state_json(&one, "zcode") &&
             json_get(&one, "domain") != NULL;
        json_free(&one);
        if (wired) {
            app_runtime_set_current(NULL);
            db_service_stop(&dbsvc);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    node_db_close(&ndb);
    return failures;
}

/* ══ ed25519 batch verification ═══════════════════════════════════════
 *
 * `ed25519_verify_batch` must return EXACTLY the conjunction of the n
 * individual `ed25519_verify` calls, on every input. Everything below is
 * a differential test against that reference loop — the loop is also the
 * implementation's own fallback path (taken when the CSPRNG refuses or
 * the working buffer cannot be allocated), so "batch == loop" is
 * simultaneously the correctness bar and the fallback-agreement bar.
 * There is no SIMD/dispatch fast path to diverge from: the batch code is
 * pure scalar C23 with one code path on every target.
 *
 * Everything here is deterministic — fixed seeds, an in-file xorshift64,
 * no wall clock and no unseeded randomness — so a failure reproduces.
 * (The batch randomisers z_i do come from the CSPRNG, but they can only
 * change the verdict with probability <= 2^-128, and never in the
 * accept-a-bad-set direction for the cases below.) */

#define EDB_MAX 512
#define EDB_MSG_MAX 40

static uint8_t edb_sig[EDB_MAX][64];
static uint8_t edb_pk[EDB_MAX][32];
static uint8_t edb_msg[EDB_MAX][EDB_MSG_MAX];
static const uint8_t *edb_msgs[EDB_MAX];
static const uint8_t *edb_sigs[EDB_MAX];
static const uint8_t *edb_pks[EDB_MAX];
static size_t edb_lens[EDB_MAX];

/* p = 2^255 - 19, little-endian. */
static const uint8_t EDB_FIELD_P_LE[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};

/* L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
static const uint8_t EDB_L_LE[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static uint64_t edb_state = 1;

static void edb_seed(uint64_t s)
{
    edb_state = s ? s : 1u;
}

static uint64_t edb_next(void)
{
    uint64_t x = edb_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    edb_state = x;
    return x;
}

static void edb_bytes(uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        b[i] = (uint8_t)(edb_next() >> 32);
}

/* Deterministically fill slots [0, n) with fresh valid signatures and
 * rebind the parallel pointer arrays. Callers then corrupt in place. */
static void edb_build(size_t n, uint64_t seed)
{
    edb_seed(seed);
    for (size_t i = 0; i < n; i++) {
        uint8_t sd[32], sk[32];
        edb_bytes(sd, 32);
        ed25519_keypair(edb_pk[i], sk, sd);
        edb_lens[i] = (size_t)(edb_next() % (EDB_MSG_MAX + 1));
        if (edb_lens[i] > 0)
            edb_bytes(edb_msg[i], edb_lens[i]);
        ed25519_sign(edb_sig[i], edb_msg[i], edb_lens[i], sk, edb_pk[i]);
        edb_msgs[i] = edb_msg[i];
        edb_sigs[i] = edb_sig[i];
        edb_pks[i] = edb_pk[i];
    }
}

/* The reference verdict: n independent ed25519_verify calls. */
static bool edb_serial(size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (!ed25519_verify(edb_sigs[i], edb_msgs[i], edb_lens[i], edb_pks[i]))
            return false;
    }
    return true;
}

/* Returns 1 (and prints) when batch and reference loop disagree. */
static int edb_diff(size_t n, const char *what)
{
    bool b = ed25519_verify_batch(edb_msgs, edb_lens, edb_sigs, edb_pks, n);
    bool s = edb_serial(n);
    if (b == s)
        return 0;
    printf("\n  DIVERGENCE n=%zu (%s): batch=%d serial=%d", n, what,
           (int)b, (int)s);
    return 1;
}

/* out = A + T where T = (0, -1) is the unique order-2 point of the curve.
 * Twisted-Edwards addition with a = -1 gives (x, y) + (0, -1) = (-x, -y),
 * so in compressed form: y' = p - y, and the sign bit (the parity of x)
 * flips because p is odd and x != 0 for any real public key.
 *
 * This is the whole 8-torsion attack: publish A' = A + T, sign honestly
 * with the secret for A, and the error point becomes e = [h]T. When h is
 * odd, e = T != O — `ed25519_verify` rejects — yet e vanishes under both
 * the textbook random-scalar batch equation (half the time, whenever the
 * randomiser z is even) and under any cofactor-cleared batch equation
 * (always, since [8]T = O). Only an explicit per-signature torsion screen
 * makes the batch agree with the single verifier here. */
static void edb_add_order2(uint8_t out[32], const uint8_t a[32])
{
    uint8_t y[32];
    memcpy(y, a, 32);
    unsigned sign = (unsigned)(y[31] >> 7);
    y[31] &= 0x7fu;

    int borrow = 0;
    for (int i = 0; i < 32; i++) {
        int d = (int)EDB_FIELD_P_LE[i] - (int)y[i] - borrow;
        borrow = d < 0;
        out[i] = (uint8_t)(d & 0xff);
    }
    out[31] = (uint8_t)((out[31] & 0x7fu) | ((1u - sign) << 7));
}

static int test_ed25519_batch(void)
{
    int failures = 0;
    enum zcl_log_level saved = zcl_log_level_get();

    /* ── Boundaries, explicitly decided ──────────────────────────
     * n == 0 is the empty conjunction: true, matching a zero-iteration
     * verify loop. A caller that needs "at least one signature" must
     * check n itself. n == 1 takes the same batch path as n == 512 —
     * there is no special case — and must agree with ed25519_verify. */
    edb_build(4, 12345);

    printf("ed25519 batch: n == 0 is the empty conjunction (true)... ");
    if (ed25519_verify_batch(edb_msgs, edb_lens, edb_sigs, edb_pks, 0))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("ed25519 batch: n == 1 accepts a valid signature... ");
    if (ed25519_verify_batch(edb_msgs, edb_lens, edb_sigs, edb_pks, 1))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("ed25519 batch: n == 1 rejects one flipped signature byte... ");
    {
        zcl_log_level_set(ZCL_LOG_OFF);
        edb_sig[0][10] ^= 0x01;
        bool b = ed25519_verify_batch(edb_msgs, edb_lens, edb_sigs, edb_pks, 1);
        bool s = edb_serial(1);
        zcl_log_level_set(saved);
        if (!b && !s) printf("OK\n");
        else { printf("FAIL (batch=%d serial=%d)\n", (int)b, (int)s); failures++; }
    }

    /* ── RFC 8032 §7.1 vectors through the batch path ────────────
     * TEST 1 is the zero-length-message case and is passed as a NULL
     * message pointer with length 0, exactly as the single path takes
     * it. TEST 2 is the 1-byte case. Both are checked alone (batch of 1)
     * and mixed in among freshly generated signatures. */
    {
        static const uint8_t rfc_msg2 = 0x72;
        uint8_t pk1[32], sig1[64], pk2[32], sig2[64];
        hex_to_bytes("d75a980182b10ab7d54bfed3c964073a"
                     "0ee172f3daa62325af021a68f707511a", pk1, sizeof(pk1));
        hex_to_bytes("e5564300c360ac729086e2cc806e828a"
                     "84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e"
                     "39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                     sig1, sizeof(sig1));
        hex_to_bytes("3d4017c3e843895a92b70aa74d1b7ebc"
                     "9c982ccf2ec4968cc0cd55f12af4660c", pk2, sizeof(pk2));
        hex_to_bytes("92a009a9f0d4cab8720e820b5f642540"
                     "a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f"
                     "3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
                     sig2, sizeof(sig2));

        printf("ed25519 batch: RFC 8032 TEST 1 (empty msg) in a batch of 1... ");
        {
            const uint8_t *m[1] = { NULL };
            const uint8_t *g[1] = { sig1 };
            const uint8_t *k[1] = { pk1 };
            size_t l[1] = { 0 };
            if (ed25519_verify_batch(m, l, g, k, 1)) printf("OK\n");
            else { printf("FAIL\n"); failures++; }
        }

        printf("ed25519 batch: RFC 8032 TEST 2 in a batch of 1... ");
        {
            const uint8_t *m[1] = { &rfc_msg2 };
            const uint8_t *g[1] = { sig2 };
            const uint8_t *k[1] = { pk2 };
            size_t l[1] = { 1 };
            if (ed25519_verify_batch(m, l, g, k, 1)) printf("OK\n");
            else { printf("FAIL\n"); failures++; }
        }

        printf("ed25519 batch: RFC 8032 vectors mixed into a batch of 6... ");
        {
            edb_build(4, 777);
            /* Shift the four generated entries up and drop the vectors in
             * at index 0 and 3 by rebinding the pointer arrays only. */
            const uint8_t *m[6], *g[6], *k[6];
            size_t l[6];
            const size_t src[6] = { 0, 0, 1, 0, 2, 3 };
            for (size_t i = 0; i < 6; i++) {
                m[i] = edb_msgs[src[i]];
                g[i] = edb_sigs[src[i]];
                k[i] = edb_pks[src[i]];
                l[i] = edb_lens[src[i]];
            }
            m[0] = NULL;  g[0] = sig1; k[0] = pk1; l[0] = 0;
            m[3] = &rfc_msg2; g[3] = sig2; k[3] = pk2; l[3] = 1;
            if (ed25519_verify_batch(m, l, g, k, 6)) printf("OK\n");
            else { printf("FAIL\n"); failures++; }

            printf("ed25519 batch: one tampered RFC vector poisons the batch... ");
            zcl_log_level_set(ZCL_LOG_OFF);
            uint8_t bad2[64];
            memcpy(bad2, sig2, 64);
            bad2[0] ^= 0x02;
            g[3] = bad2;
            bool b = ed25519_verify_batch(m, l, g, k, 6);
            bool s = ed25519_verify(bad2, &rfc_msg2, 1, pk2);
            zcl_log_level_set(saved);
            if (!b && !s) printf("OK\n");
            else { printf("FAIL (batch=%d single=%d)\n", (int)b, (int)s); failures++; }
        }
    }

    /* ── The 8-torsion regression test ───────────────────────────
     * Without a per-signature torsion screen this set is accepted by the
     * batch and rejected by ed25519_verify — a forgery acceptance, not a
     * rounding error. Measured on this code with the screen disabled:
     * accepted 16/16. Both parities of h are covered: h odd gives
     * e = T != O (must be rejected by BOTH paths), h even gives e = O
     * (a genuinely valid signature under the cofactorless verifier, which
     * BOTH paths must accept — the screen must not over-reject). */
    printf("ed25519 batch: 8-torsion pubkey A+T agrees with the single verifier... ");
    {
        uint8_t seed[32], pk[32], sk[32], pkt[32];
        for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 7 + 3);
        ed25519_keypair(pk, sk, seed);
        edb_add_order2(pkt, pk);

        int rej_ctr = -1, acc_ctr = -1, diverged = 0;
        zcl_log_level_set(ZCL_LOG_OFF);
        for (int c = 0; c < 64 && (rej_ctr < 0 || acc_ctr < 0); c++) {
            uint8_t msg[4] = { (uint8_t)c, 0xAA, 0xBB, (uint8_t)(c * 3) };
            uint8_t sig[64];
            ed25519_sign(sig, msg, sizeof(msg), sk, pkt);
            const uint8_t *m[1] = { msg };
            const uint8_t *g[1] = { sig };
            const uint8_t *k[1] = { pkt };
            size_t l[1] = { sizeof(msg) };
            bool single = ed25519_verify(sig, msg, sizeof(msg), pkt);
            bool batch = ed25519_verify_batch(m, l, g, k, 1);
            if (single != batch) diverged++;
            if (!single && rej_ctr < 0) rej_ctr = c;
            if (single && acc_ctr < 0) acc_ctr = c;
        }
        /* Hammer the rejecting case: a batch that only probabilistically
         * catches torsion would slip through with probability 2^-16. */
        int accepted = 0;
        if (rej_ctr >= 0) {
            uint8_t msg[4] = { (uint8_t)rej_ctr, 0xAA, 0xBB,
                               (uint8_t)(rej_ctr * 3) };
            uint8_t sig[64];
            ed25519_sign(sig, msg, sizeof(msg), sk, pkt);
            const uint8_t *m[1] = { msg };
            const uint8_t *g[1] = { sig };
            const uint8_t *k[1] = { pkt };
            size_t l[1] = { sizeof(msg) };
            for (int r = 0; r < 16; r++)
                if (ed25519_verify_batch(m, l, g, k, 1)) accepted++;
        }
        zcl_log_level_set(saved);

        if (diverged == 0 && rej_ctr >= 0 && acc_ctr >= 0 && accepted == 0)
            printf("OK (h-odd rejected, h-even accepted, 0/16 forgeries slipped)\n");
        else {
            printf("FAIL (diverged=%d rej_ctr=%d acc_ctr=%d forgeries_accepted=%d/16)\n",
                   diverged, rej_ctr, acc_ctr, accepted);
            failures++;
        }
    }

    /* ── Differential fuzz ───────────────────────────────────────
     * Fixed seeds; every corruption is applied at EVERY position of the
     * set, and the batch verdict must equal the reference loop's. */
    printf("ed25519 batch: differential fuzz vs the verify loop... ");
    {
        int diverged = 0;
        zcl_log_level_set(ZCL_LOG_OFF);
        for (uint64_t seed = 1; seed <= 8; seed++) {
            size_t n = 1 + (size_t)(seed % 5);

            edb_build(n, seed);
            diverged += edb_diff(n, "clean");

            for (size_t pos = 0; pos < n; pos++) {
                edb_build(n, seed);
                edb_sig[pos][(size_t)(seed * 7 + pos) % 64] ^= 0x01;
                diverged += edb_diff(n, "signature bit flip");

                edb_build(n, seed);
                edb_sig[pos][63] |= 0x80; /* S >= L: non-canonical scalar */
                diverged += edb_diff(n, "S high bit set");

                edb_build(n, seed);
                memcpy(edb_sig[pos] + 32, EDB_L_LE, 32); /* S == L exactly */
                diverged += edb_diff(n, "S == L");

                edb_build(n, seed);
                if (edb_lens[pos] == 0) edb_lens[pos] = 1;
                else edb_msg[pos][0] ^= 0x01;
                diverged += edb_diff(n, "message tamper");

                edb_build(n, seed);
                edb_pk[pos][(size_t)(seed + pos) % 32] ^= 0x01;
                diverged += edb_diff(n, "pubkey bit flip");

                edb_build(n, seed);
                memset(edb_pk[pos], 0, 32); /* identity pubkey */
                diverged += edb_diff(n, "all-zero pubkey");

                edb_build(n, seed);
                memset(edb_sig[pos], 0, 32); /* R = y:0, an order-4 point */
                diverged += edb_diff(n, "R zeroed");

                edb_build(n, seed);
                memcpy(edb_sig[pos], EDB_FIELD_P_LE, 32); /* y == p */
                diverged += edb_diff(n, "R non-canonical (y == p)");

                if (n >= 2) {
                    size_t o = (pos + 1) % n;

                    edb_build(n, seed);
                    {
                        uint8_t t[64];
                        memcpy(t, edb_sig[pos], 64);
                        memcpy(edb_sig[pos], edb_sig[o], 64);
                        memcpy(edb_sig[o], t, 64);
                    }
                    diverged += edb_diff(n, "swapped signature pair");

                    edb_build(n, seed);
                    memcpy(edb_sig[o], edb_sig[pos], 64);
                    memcpy(edb_pk[o], edb_pk[pos], 32);
                    memcpy(edb_msg[o], edb_msg[pos], EDB_MSG_MAX);
                    edb_lens[o] = edb_lens[pos];
                    diverged += edb_diff(n, "duplicate entry");
                }
            }
        }
        zcl_log_level_set(saved);
        if (diverged == 0) printf("OK\n");
        else { printf("\n  %d divergence(s)\n", diverged); failures++; }
    }

    /* ── Benchmark (opt-in: ZCL_ED25519_BATCH_BENCH=1) ───────────
     * Off by default so the group stays in the fast pool. Timed through
     * platform/clock.h, never a raw clock_gettime. */
    if (getenv("ZCL_ED25519_BATCH_BENCH")) {
        const size_t sizes[3] = { 8, 64, 512 };
        printf("\n  ed25519 batch benchmark\n");
        printf("     n |  single ver/s |   batch ver/s | speedup\n");
        for (int si = 0; si < 3; si++) {
            size_t n = sizes[si];
            edb_build(n, 999 + (uint64_t)si);
            int reps = n >= 512 ? 2 : (n >= 64 ? 8 : 40);

            int64_t t0 = clock_now_monotonic_ns();
            for (int r = 0; r < reps; r++)
                if (!edb_serial(n)) { printf("  bench serial FAILED\n"); failures++; }
            int64_t t1 = clock_now_monotonic_ns();
            for (int r = 0; r < reps; r++)
                if (!ed25519_verify_batch(edb_msgs, edb_lens, edb_sigs,
                                          edb_pks, n)) {
                    printf("  bench batch FAILED\n");
                    failures++;
                }
            int64_t t2 = clock_now_monotonic_ns();

            double sps = (double)reps * (double)n * 1e9 / (double)(t1 - t0);
            double bps = (double)reps * (double)n * 1e9 / (double)(t2 - t1);
            printf("  %4zu | %13.1f | %13.1f | %6.2fx\n", n, sps, bps,
                   bps / sps);
        }
        printf("\n");
    }

    return failures;
}

int test_zid(void)
{
    int failures = 0;

    printf("\n=== ZID Tests ===\n");

    /* ── RFC 8032 §7.1 known-answer vectors ─────────────────────── */

    failures += test_rfc8032_vector(
        "TEST 1 (empty msg)",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        NULL, 0,
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    const uint8_t msg_r = 0x72;
    failures += test_rfc8032_vector(
        "TEST 2 (1-byte 0x72)",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        &msg_r, 1,
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

    /* ── Batch verification == the verify loop, on every input ───── */

    failures += test_ed25519_batch();

    /* ── Document sign → encode → decode → verify round-trip ─────── */

    uint8_t seed[32];
    hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                 seed, sizeof(seed));
    const uint8_t body[] = "hello sovereign identity";
    const uint64_t now = 1700000000;

    struct zid_doc doc;
    printf("zid_doc_sign: fills and signs... ");
    if (zid_doc_sign(&doc, body, sizeof(body) - 1, 1, now + 3600, seed))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = zid_doc_encode(wire, sizeof(wire), &doc);
    printf("zid_doc_encode: exact wire size... ");
    if (wire_len == 51 + sizeof(body) - 1 + 64)
        printf("OK\n");
    else { printf("FAIL (len=%zu)\n", wire_len); failures++; }

    struct zid_doc back;
    printf("zid sign→encode→decode→verify round-trip... ");
    if (zid_doc_decode(&back, wire, wire_len) &&
        back.body_len == sizeof(body) - 1 &&
        memcmp(back.body, body, sizeof(body) - 1) == 0 &&
        back.seq == 1 && back.expiry == now + 3600 &&
        memcmp(back.master_pubkey, doc.master_pubkey, 32) == 0 &&
        zid_doc_verify(&back, now))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    /* ── Tamper rejection ────────────────────────────────────────── */

    printf("zid_doc_verify: flipped body byte rejected... ");
    {
        struct zid_doc t = doc;
        t.body[0] ^= 0x01;
        if (!zid_doc_verify(&t, now)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_doc_verify: wrong master pubkey rejected... ");
    {
        struct zid_doc t = doc;
        t.master_pubkey[0] ^= 0x01;
        if (!zid_doc_verify(&t, now)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_doc_verify: expired doc rejected (expiry <= now)... ");
    if (!zid_doc_verify(&doc, now + 3600)) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("zid_doc_decode: truncated buffer rejected... ");
    {
        struct zid_doc t;
        if (!zid_doc_decode(&t, wire, wire_len - 1)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_doc_decode: bad version byte rejected... ");
    {
        uint8_t bad[ZID_DOC_MAX];
        memcpy(bad, wire, wire_len);
        bad[0] = 2;
        struct zid_doc t;
        if (!zid_doc_decode(&t, bad, wire_len)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_doc_encode: undersized output buffer rejected... ");
    if (zid_doc_encode(wire, wire_len - 1, &doc) == 0) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("zid_doc_sign: oversize body rejected... ");
    {
        struct zid_doc t;
        uint8_t big[ZID_BODY_MAX + 1];
        memset(big, 0xAB, sizeof(big));
        if (!zid_doc_sign(&t, big, ZID_BODY_MAX + 1, 1, now + 1, seed))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Blinded keys ────────────────────────────────────────────── */

    printf("zid_blinded_key: deterministic... ");
    {
        uint8_t k1[32], k2[32];
        zid_blinded_key(k1, doc.master_pubkey, 100);
        zid_blinded_key(k2, doc.master_pubkey, 100);
        if (memcmp(k1, k2, 32) == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_blinded_key: differs across periods... ");
    {
        uint8_t k1[32], k2[32];
        zid_blinded_key(k1, doc.master_pubkey, 100);
        zid_blinded_key(k2, doc.master_pubkey, 101);
        if (memcmp(k1, k2, 32) != 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_blinded_key: differs across pubkeys... ");
    {
        uint8_t other_pk[32];
        memcpy(other_pk, doc.master_pubkey, 32);
        other_pk[0] ^= 0x01;
        uint8_t k1[32], k2[32];
        zid_blinded_key(k1, doc.master_pubkey, 100);
        zid_blinded_key(k2, other_pk, 100);
        if (memcmp(k1, k2, 32) != 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_blinded_key: self-consistency vector (ZIDB tag, period 42)... ");
    {
        uint8_t k1[32], k2[32], want[32];
        zid_blinded_key(k1, doc.master_pubkey, 42);
        zid_blinded_key(k2, doc.master_pubkey, 42);
        hex_to_bytes("38d696445a7024f2e004b7a4fa425aa111b9131e79bd126f4274de6a2fd58adf",
                     want, sizeof(want));
        if (memcmp(k1, k2, 32) == 0 && memcmp(k1, want, 32) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Monotonic-seq supersede rule ────────────────────────────── */

    printf("zid_doc_supersedes: higher seq supersedes... ");
    {
        struct zid_doc newer = doc;
        newer.seq = doc.seq + 1;
        if (zid_doc_supersedes(&newer, &doc)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_doc_supersedes: equal seq does not... ");
    if (!zid_doc_supersedes(&doc, &doc)) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("zid_doc_supersedes: lower seq does not... ");
    {
        struct zid_doc older = doc;
        older.seq = doc.seq + 1;
        if (!zid_doc_supersedes(&doc, &older)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_doc_supersedes: different pubkey does not... ");
    {
        struct zid_doc alien = doc;
        alien.seq = doc.seq + 100;
        alien.master_pubkey[0] ^= 0x01;
        if (!zid_doc_supersedes(&alien, &doc)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Anchor-domain tree (MMR) ────────────────────────────────── */

    printf("\n=== ZID anchor-domain tree ===\n");

    /* Deterministic record digests: SHA3-256("zid-test-leaf" ‖ seed ‖ i). */
    #define ZID_TEST_MAX_LEAVES 32
    uint8_t leaves[ZID_TEST_MAX_LEAVES][32];
    uint8_t leaves_b[ZID_TEST_MAX_LEAVES][32];
    for (uint64_t i = 0; i < ZID_TEST_MAX_LEAVES; i++) {
        uint8_t buf[13 + 1 + 8];
        memcpy(buf, "zid-test-leaf", 13);
        buf[13] = 0xA0;
        for (int b = 0; b < 8; b++) buf[14 + b] = (uint8_t)(i >> (8 * b));
        sha3_256(buf, sizeof(buf), leaves[i]);
        buf[13] = 0xB0;
        sha3_256(buf, sizeof(buf), leaves_b[i]);
    }

    /* Empty tree: zero root, prove/verify refuse. */
    printf("zid_tree: empty tree root is zero, prove refuses... ");
    {
        struct zid_tree t;
        zid_tree_init(&t);
        uint8_t root[32], proof[ZID_TREE_MAX_PEAKS][32], pr[32];
        uint32_t plen = 0;
        zid_tree_root(&t, root);
        uint8_t zero[32] = {0};
        bool empty_ok = memcmp(root, zero, 32) == 0 &&
            !zid_tree_prove_from_leaves(leaves, 0, 0, proof, &plen, pr) &&
            !zid_tree_verify(root, leaves[0], 0, 0, proof, 0);
        if (empty_ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* For each size: prove EVERY leaf from the leaf list, verify true,
     * and cross-check the rebuilt root against the incremental
     * zid_tree_append + zid_tree_root root. Peaks == popcount(n). */
    const uint64_t sizes[] = {1, 2, 3, 5, 8, 17};
    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        uint64_t n = sizes[si];
        printf("zid_tree: %llu leaves — prove+verify every leaf, roots agree... ",
               (unsigned long long)n);
        struct zid_tree t;
        zid_tree_init(&t);
        for (uint64_t i = 0; i < n; i++)
            zid_tree_append(&t, leaves[i]);
        uint8_t inc_root[32];
        zid_tree_root(&t, inc_root);

        bool ok = (t.num_peaks == (uint32_t)__builtin_popcountll(n));
        uint8_t proof[ZID_TREE_MAX_PEAKS][32], pr[32];
        for (uint64_t i = 0; ok && i < n; i++) {
            uint32_t plen = 0;
            if (!zid_tree_prove_from_leaves(leaves, n, i, proof, &plen, pr)) {
                printf("\n  prove leaf %llu failed\n", (unsigned long long)i);
                ok = false;
                break;
            }
            if (memcmp(pr, inc_root, 32) != 0) {
                printf("\n  rebuilt root != incremental root at leaf %llu\n",
                       (unsigned long long)i);
                ok = false;
                break;
            }
            if (!zid_tree_verify(inc_root, leaves[i], i, n, proof, plen)) {
                printf("\n  verify leaf %llu failed\n", (unsigned long long)i);
                ok = false;
                break;
            }
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* Tamper battery on a 17-leaf tree, leaf 7. */
    printf("zid_tree_verify: wrong root rejected... ");
    {
        uint8_t proof[ZID_TREE_MAX_PEAKS][32], root[32];
        uint32_t plen = 0;
        zid_tree_prove_from_leaves(leaves, 17, 7, proof, &plen, root);
        root[0] ^= 0x01;
        if (!zid_tree_verify(root, leaves[7], 7, 17, proof, plen)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_tree_verify: wrong index rejected... ");
    {
        uint8_t proof[ZID_TREE_MAX_PEAKS][32], root[32];
        uint32_t plen = 0;
        zid_tree_prove_from_leaves(leaves, 17, 7, proof, &plen, root);
        if (!zid_tree_verify(root, leaves[8], 8, 17, proof, plen)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_tree_verify: wrong num_leaves rejected... ");
    {
        uint8_t proof[ZID_TREE_MAX_PEAKS][32], root[32];
        uint32_t plen = 0;
        zid_tree_prove_from_leaves(leaves, 17, 7, proof, &plen, root);
        if (!zid_tree_verify(root, leaves[7], 7, 16, proof, plen)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_tree_verify: flipped sibling byte rejected... ");
    {
        uint8_t proof[ZID_TREE_MAX_PEAKS][32], root[32];
        uint32_t plen = 0;
        zid_tree_prove_from_leaves(leaves, 17, 7, proof, &plen, root);
        proof[0][0] ^= 0x01;
        if (!zid_tree_verify(root, leaves[7], 7, 17, proof, plen)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_tree_verify: digest from a different tree rejected... ");
    {
        uint8_t proof[ZID_TREE_MAX_PEAKS][32], root[32];
        uint32_t plen = 0;
        zid_tree_prove_from_leaves(leaves, 17, 7, proof, &plen, root);
        if (!zid_tree_verify(root, leaves_b[7], 7, 17, proof, plen)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_tree_verify: truncated proof rejected... ");
    {
        uint8_t proof[ZID_TREE_MAX_PEAKS][32], root[32];
        uint32_t plen = 0;
        zid_tree_prove_from_leaves(leaves, 17, 7, proof, &plen, root);
        if (plen > 0 &&
            !zid_tree_verify(root, leaves[7], 7, 17, proof, plen - 1))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* Cross-tag isolation: fold the SAME record digest as a chain-mmr
     * leaf (SHA3(0x00 ‖ digest), no "ZIDL") along the zid proof; the
     * result must differ from the zid tree root. */
    printf("zid_tree: chain-mmr-tagged leaf does not replay against zid root... ");
    {
        uint8_t proof[ZID_TREE_MAX_PEAKS][32], root[32];
        uint32_t plen = 0;
        zid_tree_prove_from_leaves(leaves, 17, 7, proof, &plen, root);

        /* Manual chain-style fold: leaf = SHA3(0x00 ‖ digest), internals
         * = SHA3(0x01 ‖ l ‖ r), same geometry (17 leaves → peaks 16+1,
         * index 7 sits in the 16-leaf peak at position 7). */
        uint8_t buf[65];
        buf[0] = 0x00;
        memcpy(buf + 1, leaves[7], 32);
        uint8_t h[32];
        sha3_256(buf, 33, h);
        uint64_t pos = 7;
        for (uint32_t i = 0; i < 4; i++) { /* 16-leaf peak: path length 4 */
            uint8_t parent[32];
            buf[0] = 0x01;
            if ((pos & 1) == 0) {
                memcpy(buf + 1, h, 32);
                memcpy(buf + 33, proof[i], 32);
            } else {
                memcpy(buf + 1, proof[i], 32);
                memcpy(buf + 33, h, 32);
            }
            sha3_256(buf, 65, parent);
            memcpy(h, parent, 32);
            pos >>= 1;
        }
        /* Bag chain-folded peak with the remaining zid proof peak. */
        struct sha3_256_ctx ctx;
        sha3_256_init(&ctx);
        uint8_t tag = 0x02;
        sha3_256_write(&ctx, &tag, 1);
        sha3_256_write(&ctx, h, 32);
        sha3_256_write(&ctx, proof[4], 32);
        uint8_t chain_root[32];
        sha3_256_finalize(&ctx, chain_root);

        if (memcmp(chain_root, root, 32) != 0) printf("OK\n");
        else { printf("FAIL (cross-tag replay succeeded)\n"); failures++; }
    }

    printf("zid_tree: root changes on append... ");
    {
        struct zid_tree t;
        zid_tree_init(&t);
        uint8_t r1[32], r2[32];
        zid_tree_append(&t, leaves[0]);
        zid_tree_root(&t, r1);
        zid_tree_append(&t, leaves[1]);
        zid_tree_root(&t, r2);
        if (memcmp(r1, r2, 32) != 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_tree: peak count == popcount(num_leaves)... ");
    {
        bool ok = true;
        for (uint64_t n = 1; n <= 23 && ok; n++) {
            struct zid_tree t;
            zid_tree_init(&t);
            for (uint64_t i = 0; i < n; i++)
                zid_tree_append(&t, leaves[i % ZID_TEST_MAX_LEAVES]);
            if (t.num_peaks != (uint32_t)__builtin_popcountll(n))
                ok = false;
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Canonical proof wire format ─────────────────────────────── */

    printf("\n=== ZID proof wire format ===\n");

    /* Round-trip: prove → encode → decode → fields match → verify. */
    const uint64_t wire_sizes[] = {1, 3, 8, 17};
    for (size_t si = 0; si < sizeof(wire_sizes) / sizeof(wire_sizes[0]); si++) {
        uint64_t n = wire_sizes[si];
        printf("zid_proof: %llu leaves — encode→decode→verify round-trip... ",
               (unsigned long long)n);
        struct zid_tree t;
        zid_tree_init(&t);
        for (uint64_t i = 0; i < n; i++)
            zid_tree_append(&t, leaves[i]);
        uint8_t root[32];
        zid_tree_root(&t, root);

        bool ok = true;
        for (uint64_t i = 0; ok && i < n; i++) {
            uint8_t proof[ZID_TREE_MAX_PEAKS][32], pr[32];
            uint32_t plen = 0;
            if (!zid_tree_prove_from_leaves(leaves, n, i, proof, &plen, pr)) {
                ok = false;
                break;
            }
            uint8_t wire[ZID_PROOF_WIRE_MAX];
            size_t wire_len = zid_proof_encode(wire, sizeof(wire),
                                               i, n, proof, plen);
            if (wire_len != 19 + (size_t)plen * 32) { ok = false; break; }

            uint64_t d_index = 0, d_n = 0;
            uint8_t d_proof[ZID_TREE_MAX_PEAKS][32];
            uint32_t d_plen = 0;
            if (!zid_proof_decode(&d_index, &d_n, d_proof, &d_plen,
                                  wire, wire_len)) { ok = false; break; }
            if (d_index != i || d_n != n || d_plen != plen ||
                memcmp(d_proof, proof, (size_t)plen * 32) != 0) {
                ok = false;
                break;
            }
            if (!zid_tree_verify(root, leaves[i], d_index, d_n,
                                 d_proof, d_plen)) { ok = false; break; }
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_proof_decode: truncated buffer rejected... ");
    {
        uint8_t proof[ZID_TREE_MAX_PEAKS][32], pr[32];
        uint32_t plen = 0;
        zid_tree_prove_from_leaves(leaves, 17, 7, proof, &plen, pr);
        uint8_t wire[ZID_PROOF_WIRE_MAX];
        size_t wire_len = zid_proof_encode(wire, sizeof(wire), 7, 17, proof, plen);
        uint64_t d_index, d_n;
        uint32_t d_plen;
        uint8_t d_proof[ZID_TREE_MAX_PEAKS][32];
        if (!zid_proof_decode(&d_index, &d_n, d_proof, &d_plen,
                              wire, wire_len - 1)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_proof_decode: wrong version rejected... ");
    {
        uint8_t proof[ZID_TREE_MAX_PEAKS][32], pr[32];
        uint32_t plen = 0;
        zid_tree_prove_from_leaves(leaves, 17, 7, proof, &plen, pr);
        uint8_t wire[ZID_PROOF_WIRE_MAX];
        size_t wire_len = zid_proof_encode(wire, sizeof(wire), 7, 17, proof, plen);
        wire[0] = 2;
        uint64_t d_index, d_n;
        uint32_t d_plen;
        uint8_t d_proof[ZID_TREE_MAX_PEAKS][32];
        if (!zid_proof_decode(&d_index, &d_n, d_proof, &d_plen,
                              wire, wire_len)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_proof_decode: proof_len field vs actual length mismatch rejected... ");
    {
        uint8_t proof[ZID_TREE_MAX_PEAKS][32], pr[32];
        uint32_t plen = 0;
        zid_tree_prove_from_leaves(leaves, 17, 7, proof, &plen, pr);
        uint8_t wire[ZID_PROOF_WIRE_MAX];
        size_t wire_len = zid_proof_encode(wire, sizeof(wire), 7, 17, proof, plen);
        wire[17] ^= 0x01; /* proof_len LE low byte at offset 17 */
        uint64_t d_index, d_n;
        uint32_t d_plen;
        uint8_t d_proof[ZID_TREE_MAX_PEAKS][32];
        if (!zid_proof_decode(&d_index, &d_n, d_proof, &d_plen,
                              wire, wire_len)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_proof_decode: oversize proof_len field rejected... ");
    {
        uint8_t wire[ZID_PROOF_WIRE_MAX];
        memset(wire, 0, sizeof(wire));
        wire[0] = ZID_PROOF_VERSION;
        wire[17] = (uint8_t)(ZID_TREE_MAX_PEAKS + 1); /* 65 > 64 */
        uint64_t d_index, d_n;
        uint32_t d_plen;
        uint8_t d_proof[ZID_TREE_MAX_PEAKS][32];
        if (!zid_proof_decode(&d_index, &d_n, d_proof, &d_plen,
                              wire, ZID_PROOF_WIRE_MAX)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_proof_encode: undersized output buffer rejected... ");
    {
        uint8_t proof[ZID_TREE_MAX_PEAKS][32], pr[32];
        uint32_t plen = 0;
        zid_tree_prove_from_leaves(leaves, 17, 7, proof, &plen, pr);
        uint8_t wire[ZID_PROOF_WIRE_MAX];
        size_t wire_len = zid_proof_encode(wire, sizeof(wire), 7, 17, proof, plen);
        if (zid_proof_encode(wire, wire_len - 1, 7, 17, proof, plen) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Release record codec ────────────────────────────────────── */

    printf("\n=== ZID release record ===\n");

    struct zid_release rel;
    memset(&rel, 0, sizeof(rel));
    snprintf(rel.name, sizeof(rel.name), "zclassic23");
    snprintf(rel.version, sizeof(rel.version), "1.0.0");
    memset(rel.manifest_root, 0x5C, 32);

    printf("zid_release: body encode→decode round-trip... ");
    {
        uint8_t body[ZID_RELEASE_BODY_MAX];
        size_t blen = zid_release_encode_body(body, sizeof(body), &rel);
        struct zid_release back;
        if (blen == 4 + 1 + 10 + 1 + 5 + 32 &&
            zid_release_decode_body(&back, body, (uint16_t)blen) &&
            strcmp(back.name, "zclassic23") == 0 &&
            strcmp(back.version, "1.0.0") == 0 &&
            memcmp(back.manifest_root, rel.manifest_root, 32) == 0)
            printf("OK\n");
        else { printf("FAIL (blen=%zu)\n", blen); failures++; }
    }

    printf("zid_release: sign→verify round-trip... ");
    {
        struct zid_doc rdoc;
        struct zid_release out;
        if (zid_release_sign(&rdoc, &rel, 7, now + 3600, seed) &&
            zid_release_verify(&rdoc, &out, now) &&
            strcmp(out.name, "zclassic23") == 0 &&
            memcmp(out.manifest_root, rel.manifest_root, 32) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_release_decode: bad name_len rejected... ");
    {
        uint8_t body[ZID_RELEASE_BODY_MAX];
        size_t blen = zid_release_encode_body(body, sizeof(body), &rel);
        body[4] = 200; /* name_len beyond ZID_RELEASE_NAME_MAX */
        struct zid_release out;
        if (!zid_release_decode_body(&out, body, (uint16_t)blen)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_release_decode: truncated body rejected... ");
    {
        uint8_t body[ZID_RELEASE_BODY_MAX];
        size_t blen = zid_release_encode_body(body, sizeof(body), &rel);
        struct zid_release out;
        if (!zid_release_decode_body(&out, body, (uint16_t)(blen - 1)))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_release_decode: wrong tag rejected... ");
    {
        uint8_t body[ZID_RELEASE_BODY_MAX];
        size_t blen = zid_release_encode_body(body, sizeof(body), &rel);
        body[0] = 'X';
        struct zid_release out;
        if (!zid_release_decode_body(&out, body, (uint16_t)blen)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_release_decode: non-printable name rejected... ");
    {
        struct zid_release bad = rel;
        bad.name[2] = '\x01';
        uint8_t body[ZID_RELEASE_BODY_MAX];
        struct zid_release out;
        if (zid_release_encode_body(body, sizeof(body), &bad) == 0 &&
            !zid_release_decode_body(&out, (const uint8_t *)"ZIDR\x03" "a\x01" "b"
                                     "\x01" "v" "00000000000000000000000000000000", 42))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_release_verify: signature over wrong body rejected... ");
    {
        /* A validly-signed doc whose body is NOT this release record. */
        struct zid_doc rdoc;
        struct zid_release out;
        const uint8_t other_body[] = "not a release record at all";
        zid_doc_sign(&rdoc, other_body, sizeof(other_body) - 1, 1,
                     now + 3600, seed);
        if (!zid_release_verify(&rdoc, &out, now)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_release_verify: tampered signed body rejected... ");
    {
        struct zid_doc rdoc;
        zid_release_sign(&rdoc, &rel, 7, now + 3600, seed);
        rdoc.body[rdoc.body_len - 1] ^= 0x01; /* flip a manifest_root byte */
        struct zid_release out;
        if (!zid_release_verify(&rdoc, &out, now)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_release_verify: expired doc rejected... ");
    {
        struct zid_doc rdoc;
        zid_release_sign(&rdoc, &rel, 7, now + 100, seed);
        struct zid_release out;
        if (!zid_release_verify(&rdoc, &out, now + 100)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_release_verify: NULL rel_out still verifies... ");
    {
        struct zid_doc rdoc;
        zid_release_sign(&rdoc, &rel, 7, now + 3600, seed);
        if (zid_release_verify(&rdoc, NULL, now)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Domain batching (record digest → domain root) ───────────── */

    printf("\n=== ZID domain batching ===\n");

    /* The digest convention is pinned two ways: against a direct
     * sha3_256 of the same wire bytes (no tag, no length prefix), and
     * against a frozen golden hex so any drift in the doc wire layout
     * or the hash fails loudly. */
    printf("zid_record_digest: SHA3-256 of canonical wire bytes (convention)... ");
    uint8_t batch_doc_wires[3][ZID_DOC_MAX];
    size_t batch_doc_lens[3];
    uint8_t batch_digests[3][32];
    {
        struct zid_doc rdoc;
        zid_release_sign(&rdoc, &rel, 7, now + 3600, seed);
        uint8_t w[ZID_DOC_MAX];
        size_t wlen = zid_doc_encode(w, sizeof(w), &rdoc);
        uint8_t d_helper[32], d_direct[32];
        zid_record_digest(d_helper, w, wlen);
        sha3_256(w, wlen, d_direct);
        if (wlen > 0 && memcmp(d_helper, d_direct, 32) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid_record_digest: golden vector (frozen bytes)... ");
    {
        static const char *GOLDEN =
            "8fb209208614b3bb2d6b34e10c71d7aded8466039476afef5dd1df0ef4474286";
        struct zid_doc rdoc;
        zid_release_sign(&rdoc, &rel, 7, now + 3600, seed);
        uint8_t w[ZID_DOC_MAX];
        size_t wlen = zid_doc_encode(w, sizeof(w), &rdoc);
        uint8_t d[32], want[32];
        zid_record_digest(d, w, wlen);
        hex_to_bytes(GOLDEN, want, sizeof(want));
        if (memcmp(d, want, 32) == 0) {
            printf("OK\n");
        } else {
            printf("FAIL (got ");
            for (int i = 0; i < 32; i++) printf("%02x", d[i]);
            printf(")\n");
            failures++;
        }
    }

    /* Three distinct release docs → digests → root via the batch helper
     * must equal the manual init/append/root fold. */
    printf("zid_tree_root_from_digests: root from N docs == manual fold... ");
    {
        const char *names[3] = {"alpha", "beta", "gamma"};
        bool built = true;
        for (int i = 0; i < 3 && built; i++) {
            struct zid_release r;
            memset(&r, 0, sizeof(r));
            snprintf(r.name, sizeof(r.name), "%s", names[i]);
            snprintf(r.version, sizeof(r.version), "0.1");
            memset(r.manifest_root, 0xA0 + i, 32);
            struct zid_doc d;
            if (!zid_release_sign(&d, &r, 1, now + 3600, seed)) {
                built = false;
                break;
            }
            batch_doc_lens[i] = zid_doc_encode(batch_doc_wires[i],
                                               sizeof(batch_doc_wires[i]), &d);
            if (batch_doc_lens[i] == 0) {
                built = false;
                break;
            }
            zid_record_digest(batch_digests[i], batch_doc_wires[i],
                              batch_doc_lens[i]);
        }
        uint8_t root_helper[32], root_manual[32];
        struct zid_tree t;
        zid_tree_init(&t);
        for (int i = 0; i < 3; i++)
            zid_tree_append(&t, batch_digests[i]);
        zid_tree_root(&t, root_manual);
        if (built &&
            zid_tree_root_from_digests((const uint8_t (*)[32])batch_digests,
                                       3, root_helper) &&
            memcmp(root_helper, root_manual, 32) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid domain batch: prove + verify one doc's digest... ");
    {
        uint8_t root[32];
        zid_tree_root_from_digests((const uint8_t (*)[32])batch_digests, 3,
                                   root);
        uint8_t proof[ZID_TREE_MAX_PEAKS][32], pr[32];
        uint32_t plen = 0;
        bool ok = zid_tree_prove_from_leaves(
                      (const uint8_t (*)[32])batch_digests, 3, 1,
                      proof, &plen, pr) &&
                  memcmp(pr, root, 32) == 0 &&
                  zid_tree_verify(root, batch_digests[1], 1, 3, proof, plen);
        /* Wrong root → reject. */
        uint8_t wrong_root[32];
        memcpy(wrong_root, root, 32);
        wrong_root[0] ^= 0x01;
        ok = ok && !zid_tree_verify(wrong_root, batch_digests[1], 1, 3,
                                    proof, plen);
        /* Wrong leaf (digest of doc 0 at index 1) → reject. */
        ok = ok && !zid_tree_verify(root, batch_digests[0], 1, 3,
                                    proof, plen);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    failures += test_zid_domain_store();
    /* ── ZID on-chain anchor overlay (lokad "ZID\0") ────────────────
     *
     * The on-chain half of the identity layer: ANCHOR / ROTATE / REVOKE of a
     * 32-byte ed25519 master key inside a standard OP_RETURN. Round-trips,
     * frozen wire vectors, pedantic negatives, and the relay cap. */

    uint8_t anchor_key_a[ZID_ANCHOR_PUBKEY_LEN];
    uint8_t anchor_key_b[ZID_ANCHOR_PUBKEY_LEN];
    for (int i = 0; i < ZID_ANCHOR_PUBKEY_LEN; i++) {
        anchor_key_a[i] = (uint8_t)(i + 1);      /* 01..20 */
        anchor_key_b[i] = (uint8_t)(i + 0x21);   /* 21..40 */
    }

    printf("zid anchor: ANCHOR build+parse roundtrip... ");
    {
        uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
        size_t len = zid_anchor_build_anchor(script, sizeof(script),
                                             anchor_key_a);
        struct zid_anchor_message m;
        bool ok = len == 43 && zid_anchor_parse(script, len, &m) &&
                  m.version == ZID_ANCHOR_VERSION &&
                  m.command == ZID_ANCHOR_CMD_ANCHOR &&
                  !m.has_old_pubkey &&
                  memcmp(m.pubkey, anchor_key_a, 32) == 0 &&
                  strcmp(zid_anchor_command_name(m.command), "anchor") == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL (len=%zu)\n", len); failures++; }
    }

    printf("zid anchor: ROTATE build+parse roundtrip (old -> new)... ");
    {
        uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
        size_t len = zid_anchor_build_rotate(script, sizeof(script),
                                             anchor_key_a, anchor_key_b);
        struct zid_anchor_message m;
        bool ok = len == ZID_ANCHOR_SCRIPT_MAX &&
                  zid_anchor_parse(script, len, &m) &&
                  m.command == ZID_ANCHOR_CMD_ROTATE &&
                  m.has_old_pubkey &&
                  memcmp(m.old_pubkey, anchor_key_a, 32) == 0 &&
                  memcmp(m.pubkey, anchor_key_b, 32) == 0 &&
                  strcmp(zid_anchor_command_name(m.command), "rotate") == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL (len=%zu)\n", len); failures++; }
    }

    printf("zid anchor: REVOKE build+parse roundtrip... ");
    {
        uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
        size_t len = zid_anchor_build_revoke(script, sizeof(script),
                                             anchor_key_b);
        struct zid_anchor_message m;
        bool ok = len == 43 && zid_anchor_parse(script, len, &m) &&
                  m.command == ZID_ANCHOR_CMD_REVOKE &&
                  !m.has_old_pubkey &&
                  memcmp(m.pubkey, anchor_key_b, 32) == 0 &&
                  strcmp(zid_anchor_command_name(m.command), "revoke") == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL (len=%zu)\n", len); failures++; }
    }

    /* ── FROZEN GOLDEN VECTORS ──────────────────────────────────────
     *
     * Byte-for-byte wire images for key_a = 01..20 and key_b = 21..40.
     * Layout: 6a | 04 "ZID\0" | 01 01 | 01 <cmd> | 20 <key> [| 20 <key>].
     * If one of these ever needs editing, the ZID wire format changed and
     * every already-published anchor stopped parsing — that is a versioned
     * protocol change, never a test fix. */

    printf("zid anchor: ANCHOR matches frozen golden vector... ");
    {
        uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
        size_t len = zid_anchor_build_anchor(script, sizeof(script),
                                             anchor_key_a);
        if (zid_anchor_golden_matches(script, len,
                "6a045a4944000101010120"
                "0102030405060708090a0b0c0d0e0f10"
                "1112131415161718191a1b1c1d1e1f20"))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: ROTATE matches frozen golden vector... ");
    {
        uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
        size_t len = zid_anchor_build_rotate(script, sizeof(script),
                                             anchor_key_a, anchor_key_b);
        if (zid_anchor_golden_matches(script, len,
                "6a045a4944000101010220"
                "0102030405060708090a0b0c0d0e0f10"
                "1112131415161718191a1b1c1d1e1f20"
                "20"
                "2122232425262728292a2b2c2d2e2f30"
                "3132333435363738393a3b3c3d3e3f40"))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: REVOKE matches frozen golden vector... ");
    {
        uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
        size_t len = zid_anchor_build_revoke(script, sizeof(script),
                                             anchor_key_b);
        if (zid_anchor_golden_matches(script, len,
                "6a045a4944000101010320"
                "2122232425262728292a2b2c2d2e2f30"
                "3132333435363738393a3b3c3d3e3f40"))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: golden vectors parse back to their commands... ");
    {
        struct zid_anchor_message m;
        uint8_t s[ZID_ANCHOR_SCRIPT_MAX];
        size_t n = hex_to_bytes("6a045a4944000101010220"
                                "0102030405060708090a0b0c0d0e0f10"
                                "1112131415161718191a1b1c1d1e1f20"
                                "20"
                                "2122232425262728292a2b2c2d2e2f30"
                                "3132333435363738393a3b3c3d3e3f40",
                                s, sizeof(s));
        bool ok = n == ZID_ANCHOR_SCRIPT_MAX && zid_anchor_parse(s, n, &m) &&
                  m.command == ZID_ANCHOR_CMD_ROTATE &&
                  memcmp(m.old_pubkey, anchor_key_a, 32) == 0 &&
                  memcmp(m.pubkey, anchor_key_b, 32) == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Pedantic negatives ─────────────────────────────────────────*/

    printf("zid anchor: every truncation of a valid script rejects... ");
    {
        uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
        size_t len = zid_anchor_build_rotate(script, sizeof(script),
                                             anchor_key_a, anchor_key_b);
        bool all_reject = len == ZID_ANCHOR_SCRIPT_MAX;
        for (size_t cut = 0; cut < len; cut++) {
            struct zid_anchor_message m;
            if (zid_anchor_parse(script, cut, &m)) { all_reject = false; break; }
        }
        if (all_reject) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: trailing byte after the last push rejects... ");
    {
        uint8_t script[ZID_ANCHOR_SCRIPT_MAX + 8];
        size_t len = zid_anchor_build_anchor(script, ZID_ANCHOR_SCRIPT_MAX,
                                             anchor_key_a);
        struct zid_anchor_message m;
        script[len] = 0x00;
        bool ok = len > 0 && zid_anchor_parse(script, len, &m) &&
                  !zid_anchor_parse(script, len + 1, &m) &&
                  m.command == ZID_ANCHOR_CMD_INVALID &&
                  m.version == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: wrong version byte rejects (dispatched first)... ");
    {
        struct zid_anchor_message m;
        bool all_reject = true;
        const uint8_t bad_versions[] = {0, 2, 3, 0x7f, 0xff};
        for (size_t i = 0; i < sizeof(bad_versions); i++) {
            uint8_t s[ZID_ANCHOR_SCRIPT_MAX];
            size_t n = zid_anchor_handmade(s, "\x5a\x49\x44\x00",
                                           bad_versions[i],
                                           ZID_ANCHOR_CMD_ANCHOR,
                                           anchor_key_a, 32);
            if (zid_anchor_parse(s, n, &m)) { all_reject = false; break; }
        }
        /* Control: the same assembler with the right version DOES parse. */
        uint8_t good[ZID_ANCHOR_SCRIPT_MAX];
        size_t gn = zid_anchor_handmade(good, "\x5a\x49\x44\x00",
                                        ZID_ANCHOR_VERSION,
                                        ZID_ANCHOR_CMD_ANCHOR,
                                        anchor_key_a, 32);
        if (all_reject && zid_anchor_parse(good, gn, &m)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: wrong lokad rejects (ZNAM/ZANC/ZID-no-NUL)... ");
    {
        struct zid_anchor_message m;
        const char *bad[] = { "ZNAM", "ZANC", "ZIDX", "\x5a\x49\x44\x01",
                              "\x00\x44\x49\x5a" };
        bool all_reject = true;
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            uint8_t s[ZID_ANCHOR_SCRIPT_MAX];
            size_t n = zid_anchor_handmade(s, bad[i], ZID_ANCHOR_VERSION,
                                           ZID_ANCHOR_CMD_ANCHOR,
                                           anchor_key_a, 32);
            if (zid_anchor_parse(s, n, &m)) { all_reject = false; break; }
        }
        if (all_reject) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: unknown command byte rejects... ");
    {
        struct zid_anchor_message m;
        const uint8_t bad_cmds[] = {0, 4, 5, 0x80, 0xff};
        bool all_reject = true;
        for (size_t i = 0; i < sizeof(bad_cmds); i++) {
            uint8_t s[ZID_ANCHOR_SCRIPT_MAX];
            size_t n = zid_anchor_handmade(s, "\x5a\x49\x44\x00",
                                           ZID_ANCHOR_VERSION, bad_cmds[i],
                                           anchor_key_a, 32);
            if (zid_anchor_parse(s, n, &m) ||
                zid_anchor_command_valid(bad_cmds[i])) {
                all_reject = false;
                break;
            }
        }
        if (all_reject) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: wrong-length pubkey push rejects (31/33/0/64)... ");
    {
        struct zid_anchor_message m;
        uint8_t big[64];
        memcpy(big, anchor_key_a, 32);
        memcpy(big + 32, anchor_key_b, 32);
        const size_t bad_lens[] = {0, 1, 31, 33, 64};
        bool all_reject = true;
        for (size_t i = 0; i < sizeof(bad_lens) / sizeof(bad_lens[0]); i++) {
            uint8_t s[ZID_ANCHOR_SCRIPT_MAX + 64];
            size_t n = zid_anchor_handmade(s, "\x5a\x49\x44\x00",
                                           ZID_ANCHOR_VERSION,
                                           ZID_ANCHOR_CMD_ANCHOR,
                                           big, bad_lens[i]);
            if (zid_anchor_parse(s, n, &m)) { all_reject = false; break; }
        }
        if (all_reject) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: ROTATE missing its second key push rejects... ");
    {
        /* A ROTATE body carrying only ONE key is a truncated rotation; it
         * must never be read as an ANCHOR of that key. */
        struct zid_anchor_message m;
        uint8_t s[ZID_ANCHOR_SCRIPT_MAX];
        size_t n = zid_anchor_handmade(s, "\x5a\x49\x44\x00",
                                       ZID_ANCHOR_VERSION,
                                       ZID_ANCHOR_CMD_ROTATE,
                                       anchor_key_a, 32);
        if (!zid_anchor_parse(s, n, &m) &&
            m.command == ZID_ANCHOR_CMD_INVALID)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: all-zero key rejects on build and on parse... ");
    {
        uint8_t zero[ZID_ANCHOR_PUBKEY_LEN] = {0};
        uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
        struct zid_anchor_message m;
        uint8_t s[ZID_ANCHOR_SCRIPT_MAX];
        size_t n = zid_anchor_handmade(s, "\x5a\x49\x44\x00",
                                       ZID_ANCHOR_VERSION,
                                       ZID_ANCHOR_CMD_ANCHOR, zero, 32);
        bool ok = zid_anchor_build_anchor(script, sizeof(script), zero) == 0 &&
                  zid_anchor_build_revoke(script, sizeof(script), zero) == 0 &&
                  zid_anchor_build_rotate(script, sizeof(script),
                                          zero, anchor_key_a) == 0 &&
                  zid_anchor_build_rotate(script, sizeof(script),
                                          anchor_key_a, zero) == 0 &&
                  !zid_anchor_parse(s, n, &m);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: self-ROTATE (old == new) rejects both ways... ");
    {
        uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
        size_t off = 0;
        uint8_t s[ZID_ANCHOR_SCRIPT_MAX];
        s[off++] = 0x6a;
        off = zid_anchor_push(s, off, (const uint8_t *)"\x5a\x49\x44\x00", 4);
        uint8_t v = ZID_ANCHOR_VERSION, c = ZID_ANCHOR_CMD_ROTATE;
        off = zid_anchor_push(s, off, &v, 1);
        off = zid_anchor_push(s, off, &c, 1);
        off = zid_anchor_push(s, off, anchor_key_a, 32);
        off = zid_anchor_push(s, off, anchor_key_a, 32);

        struct zid_anchor_message m;
        bool ok = zid_anchor_build_rotate(script, sizeof(script),
                                          anchor_key_a, anchor_key_a) == 0 &&
                  off == ZID_ANCHOR_SCRIPT_MAX &&
                  !zid_anchor_parse(s, off, &m);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: NULL / empty-buffer arguments reject... ");
    {
        uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
        struct zid_anchor_message m;
        bool ok = zid_anchor_build_anchor(NULL, 64, anchor_key_a) == 0 &&
                  zid_anchor_build_anchor(script, 0, anchor_key_a) == 0 &&
                  zid_anchor_build_anchor(script, sizeof(script), NULL) == 0 &&
                  zid_anchor_build_revoke(script, sizeof(script), NULL) == 0 &&
                  zid_anchor_build_rotate(script, sizeof(script),
                                          NULL, anchor_key_b) == 0 &&
                  zid_anchor_build_rotate(script, sizeof(script),
                                          anchor_key_a, NULL) == 0 &&
                  !zid_anchor_parse(NULL, 43, &m) &&
                  !zid_anchor_parse(script, 0, &m) &&
                  !zid_anchor_parse(script, 43, NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: non-OP_RETURN first byte rejects... ");
    {
        uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
        size_t len = zid_anchor_build_anchor(script, sizeof(script),
                                             anchor_key_a);
        struct zid_anchor_message m;
        script[0] = 0x6b;
        if (len > 0 && !zid_anchor_parse(script, len, &m)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Relay cap (MAX_OP_RETURN_RELAY = 223) ──────────────────────*/

    printf("zid anchor: undersized output buffers refuse to emit... ");
    {
        bool all_refuse = true;
        for (size_t cap = 1; cap < 43; cap++) {
            uint8_t small[64];
            if (zid_anchor_build_anchor(small, cap, anchor_key_a) != 0) {
                all_refuse = false;
                break;
            }
        }
        for (size_t cap = 1; cap < ZID_ANCHOR_SCRIPT_MAX; cap++) {
            uint8_t small[ZID_ANCHOR_SCRIPT_MAX];
            if (zid_anchor_build_rotate(small, cap,
                                        anchor_key_a, anchor_key_b) != 0) {
                all_refuse = false;
                break;
            }
        }
        if (all_refuse) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid anchor: a huge buffer still emits at most 223 bytes... ");
    {
        uint8_t big[1024];
        size_t a = zid_anchor_build_anchor(big, sizeof(big), anchor_key_a);
        size_t r = zid_anchor_build_rotate(big, sizeof(big),
                                           anchor_key_a, anchor_key_b);
        size_t v = zid_anchor_build_revoke(big, sizeof(big), anchor_key_b);
        bool ok = a > 0 && r > 0 && v > 0 &&
                  a <= MAX_OP_RETURN_RELAY && r <= MAX_OP_RETURN_RELAY &&
                  v <= MAX_OP_RETURN_RELAY &&
                  r == ZID_ANCHOR_SCRIPT_MAX;   /* ROTATE is the largest form */
        if (ok) printf("OK\n");
        else { printf("FAIL (%zu %zu %zu)\n", a, r, v); failures++; }
    }

    printf("zid anchor: parse refuses a script over the 223-byte cap... ");
    {
        /* Well-formed prefix, padded past the standardness ceiling: an
         * OP_RETURN that could never have relayed is not a ZID anchor. */
        uint8_t over[ZID_ANCHOR_RELAY_MAX + 64];
        memset(over, 0x00, sizeof(over));
        size_t len = zid_anchor_build_anchor(over, ZID_ANCHOR_SCRIPT_MAX,
                                             anchor_key_a);
        struct zid_anchor_message m;
        bool ok = len == 43 &&
                  !zid_anchor_parse(over, ZID_ANCHOR_RELAY_MAX + 1, &m) &&
                  !zid_anchor_parse(over, sizeof(over), &m);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("=== ZID: %d failure(s) ===\n", failures);
    return failures;
}
