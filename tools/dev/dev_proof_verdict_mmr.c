/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Append-only signed MMR over accepted-proof verdict leaves, and
 *          the pure admission, sampling and divergence rules over it. */
#include "dev_proof_verdict_mmr.h"

#include "dev_proof_observation_walk.h"
#include "dev_proof_signer.h"
#include "verify_attest.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/directory_compat.h"
#include "platform/process_lock.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
#include "vcs/vcs_object.h"

#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VM_WIRE VCS_ZCODE_OBSERVATION_MMR_WIRE_BYTES
#define VM_BATCH VCS_ZCODE_OBSERVATION_MMR_BATCH_MAX
#define VM_FILE_MAX (32u * 1024u * 1024u)
#define VM_SAMPLE_DOMAIN "zcl.dev_proof.verdict_reuse_sample.v1"

static bool vm_fail(char *why, size_t cap, const char *reason)
{
    if (why != NULL && cap > 0) {
        size_t n = strlen(reason);
        if (n >= cap) n = cap - 1;
        memcpy(why, reason, n);
        why[n] = '\0';
    }
    return false;
}

const char *zcl_dev_vmmr_dir(void)
{
    const char *s = getenv("ZCL_DEV_PROOF_VERDICT_MMR");
    return s && s[0] == '/' && strlen(s) < PATH_MAX - 64 ? s : NULL;
}

static bool vm_path(const char *dir, const char *leaf, char *out, size_t cap)
{
    return dir && dir[0] && snprintf(out, cap, "%s/%s", dir, leaf) < (int)cap;
}

/* The whole file, bounded. *present is false for an absent file. */
static bool vm_read_file(const char *path, uint8_t **bytes, size_t *len,
                         bool *present)
{
    FILE *f = fopen(path, "rb");
    long size;
    uint8_t *buf;
    *bytes = NULL;
    *len = 0;
    *present = f != NULL;
    if (!f) return errno == ENOENT;
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 ||
        (unsigned long)size > VM_FILE_MAX || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }
    buf = zcl_malloc((size_t)size + 1, "vmmr_chain_read");
    if (!buf || fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return false;
    }
    fclose(f);
    *bytes = buf;
    *len = (size_t)size;
    return true;
}

void zcl_dev_vmmr_release(struct zcl_dev_vmmr_chain *chain)
{
    if (!chain) return;
    free(chain->roots);
    memset(chain, 0, sizeof(*chain));
}

static bool vm_issuer(uint8_t issuer[32])
{
    bool present = false;
    const char *signer_why = NULL;
    return zcl_dev_proof_signer_public(issuer, &present, &signer_why) &&
           present;
}

/* Verify one record at p and fold it into the chain. Returns bytes used. */
static size_t vm_record_step(const uint8_t *p, size_t remain,
                             const uint8_t issuer[32],
                             struct zcl_dev_vmmr_chain *chain, uint8_t **cap)
{
    size_t count, need;
    struct vcs_zcode_observation_mmr_checkpoint cp;
    if (remain < 1) return 0;
    count = p[0];
    need = 1 + (size_t)VM_WIRE + count * 32u;
    if (count == 0 || count > VM_BATCH || remain < need ||
        chain->leaf_count > ZCL_DEV_VMMR_MAX_LEAVES - count ||
        !vcs_zcode_observation_mmr_parse(p + 1, VM_WIRE, issuer, &cp) ||
        !vcs_zcode_observation_mmr_verify_extension(
            chain->records ? &chain->head : NULL, &cp, p + 1 + VM_WIRE,
            count, issuer))
        return 0;
    {
        uint8_t *grown = zcl_realloc(*cap, ((size_t)chain->leaf_count + count) * 32u,
                                     "vmmr_chain_roots");
        if (!grown) return 0;
        *cap = grown;
        memcpy(grown + (size_t)chain->leaf_count * 32u, p + 1 + VM_WIRE,
               count * 32u);
    }
    chain->leaf_count += (uint32_t)count;
    chain->records++;
    chain->head = cp;
    return need;
}

bool zcl_dev_vmmr_load(const char *dir, struct zcl_dev_vmmr_chain *out,
                       char *why, size_t why_len)
{
    char path[PATH_MAX];
    uint8_t *bytes = NULL, *roots = NULL, issuer[32];
    size_t len = 0, off = 0, used;
    bool present = false;
    struct zcl_dev_vmmr_chain chain = {0};
    if (!out) return vm_fail(why, why_len, "verdict_mmr_arguments");
    memset(out, 0, sizeof(*out));
    if (!vm_path(dir, "chain.log", path, sizeof(path)))
        return vm_fail(why, why_len, "verdict_mmr_path");
    if (!vm_read_file(path, &bytes, &len, &present))
        return vm_fail(why, why_len, "verdict_mmr_unreadable");
    if (!present || len == 0) {
        free(bytes);
        return true;
    }
    if (!vm_issuer(issuer)) {
        free(bytes);
        return vm_fail(why, why_len, "verdict_mmr_no_signer");
    }
    while (off < len) {
        used = vm_record_step(bytes + off, len - off, issuer, &chain, &roots);
        if (used == 0) {
            free(bytes);
            free(roots);
            return vm_fail(why, why_len, "verdict_mmr_history_invalid");
        }
        off += used;
    }
    free(bytes);
    chain.roots = roots;
    if (!vcs_zcode_observation_mmr_root(&chain.head, chain.head_root)) {
        free(roots);
        return vm_fail(why, why_len, "verdict_mmr_history_invalid");
    }
    *out = chain;
    return true;
}

struct vm_extend {
    const struct vcs_zcode_observation_mmr_checkpoint *prev;
    const uint8_t *roots;
    size_t count;
    int64_t now;
    struct vcs_zcode_observation_mmr_checkpoint next;
};

static bool vm_extend_use(const uint8_t seed[32], const uint8_t pubkey[32],
                          void *ctx)
{
    struct vm_extend *e = ctx;
    return vcs_zcode_observation_mmr_extend(e->prev, e->roots, e->count,
                                            e->now, seed, pubkey, &e->next);
}

/* Build the record bytes for every chunk of `roots`, chained from head. */
static uint8_t *vm_build_records(const struct zcl_dev_vmmr_chain *chain,
                                 const uint8_t *roots, size_t count,
                                 int64_t now, const uint8_t issuer[32],
                                 size_t *out_len)
{
    size_t chunks = (count + VM_BATCH - 1) / VM_BATCH, off = 0, done = 0;
    uint8_t *buf = zcl_malloc(chunks + count * 32u + chunks * VM_WIRE,
                              "vmmr_records");
    struct vcs_zcode_observation_mmr_checkpoint prev = chain->head;
    bool have_prev = chain->records != 0;
    const char *signer_why = NULL;
    if (!buf) return NULL;
    while (done < count) {
        size_t n = count - done < VM_BATCH ? count - done : VM_BATCH;
        struct vm_extend e = { have_prev ? &prev : NULL, roots + done * 32u,
                               n, now, {0} };
        if (e.prev && e.prev->observed_unix > now) e.now = e.prev->observed_unix;
        if (!zcl_dev_proof_signer_lend_seed(vm_extend_use, &e, &signer_why) ||
            !vcs_zcode_observation_mmr_verify_extension(
                e.prev, &e.next, e.roots, n, issuer)) {
            free(buf);
            return NULL;
        }
        buf[off++] = (uint8_t)n;
        if (!vcs_zcode_observation_mmr_serialize(&e.next, buf + off)) {
            free(buf);
            return NULL;
        }
        off += VM_WIRE;
        memcpy(buf + off, e.roots, n * 32u);
        off += n * 32u;
        prev = e.next;
        have_prev = true;
        done += n;
    }
    *out_len = off;
    return buf;
}

static bool vm_write_records(const char *path, const uint8_t *records,
                             size_t len)
{
    FILE *f = fopen(path, "ab");
    bool ok = f && fwrite(records, 1, len, f) == len && fflush(f) == 0;
    if (f && fclose(f) != 0) ok = false;
    return ok;
}

bool zcl_dev_vmmr_append(const char *dir, const uint8_t (*roots)[32],
                         size_t count, int64_t now_unix,
                         struct zcl_dev_vmmr_chain *out,
                         char *why, size_t why_len)
{
    struct zcl_dev_vmmr_chain chain;
    char path[PATH_MAX], lock_path[PATH_MAX];
    uint8_t issuer[32], *records;
    size_t len = 0;
    struct platform_process_lock lock;
    bool ok;
    if (!roots || count == 0 || now_unix <= 0 ||
        !vm_path(dir, "chain.log", path, sizeof(path)) ||
        !vm_path(dir, "chain.lock", lock_path, sizeof(lock_path)))
        return vm_fail(why, why_len, "verdict_mmr_arguments");
    if (!platform_directory_ensure(dir, 0700))
        return vm_fail(why, why_len, "verdict_mmr_dir");
    platform_process_lock_init(&lock);
    if (!platform_process_lock_acquire(&lock, lock_path, true))
        return vm_fail(why, why_len, "verdict_mmr_lock");
    if (!zcl_dev_vmmr_load(dir, &chain, why, why_len)) {
        platform_process_lock_release(&lock);
        return false;
    }
    if (count > ZCL_DEV_VMMR_MAX_LEAVES - chain.leaf_count ||
        !vm_issuer(issuer)) {
        zcl_dev_vmmr_release(&chain);
        platform_process_lock_release(&lock);
        return vm_fail(why, why_len, "verdict_mmr_full_or_no_signer");
    }
    records = vm_build_records(&chain, &roots[0][0], count, now_unix, issuer,
                               &len);
    zcl_dev_vmmr_release(&chain);
    if (!records) {
        platform_process_lock_release(&lock);
        return vm_fail(why, why_len, "verdict_mmr_extend_refused");
    }
    ok = vm_write_records(path, records, len);
    free(records);
    if (ok && out) ok = zcl_dev_vmmr_load(dir, out, why, why_len);
    platform_process_lock_release(&lock);
    if (!ok) return vm_fail(why, why_len, "verdict_mmr_write_or_reload_failed");
    return true;
}

size_t zcl_dev_vmmr_test_argv(const char *binary, const char *only,
                              const char **argv, size_t argv_cap)
{
    if (!binary || !binary[0] || !only || !only[0] || !argv ||
        argv_cap < ZCL_DEV_VMMR_TEST_ARGC + 1)
        return 0;
    argv[0] = binary;
    argv[1] = only;
    argv[2] = "--cold-audit";
    argv[3] = "--collect-observations";
    argv[4] = "--activate-proof-contracts";
    argv[5] = NULL;
    return ZCL_DEV_VMMR_TEST_ARGC;
}

/* ── Adoption ───────────────────────────────────────────────────────────── */

struct vm_line {
    char group[ZCL_DEV_VERDICT_LEAF_GROUP_BYTES];
    uint8_t key[32];
    uint8_t root[32];
};

/* "OBSERVATION group=G verdict=PASS key=K root=R ..." on one line. */
static bool vm_parse_line(const char *line, size_t n, struct vm_line *out)
{
    char buf[512], group[ZCL_DEV_VERDICT_LEAF_GROUP_BYTES], key[72], root[72];
    if (n < 20 || n >= sizeof(buf) ||
        memcmp(line, "OBSERVATION group=", 18) != 0)
        return false;
    memcpy(buf, line, n);
    buf[n] = '\0';
    if (sscanf(buf, "OBSERVATION group=%127s verdict=PASS key=%71s root=%71s",
               group, key, root) != 3)
        return false;
    memcpy(out->group, group, sizeof(out->group));
    return zcl_hex_decode_lower(key, out->key, 32) &&
           zcl_hex_decode_lower(root, out->root, 32);
}

/* Re-read the pair store's leaf and re-verify it for exactly this line. */
static bool vm_leaf_load(const char *store, const struct vm_line *l,
                         uint8_t wire[ZCL_DEV_VERDICT_LEAF_WIRE_BYTES])
{
    uint8_t *raw = NULL, derived[32];
    size_t len = 0;
    struct zcl_dev_verdict_leaf_v1 leaf;
    char why[80];
    bool ok;
    if (vcs_object_load_raw_bounded(store, l->root,
                                    ZCL_DEV_VERDICT_LEAF_WIRE_BYTES, &raw,
                                    &len) != 0)
        return false;
    ok = zcl_dev_verdict_leaf_parse(raw, len, &leaf, why, sizeof(why)) &&
         zcl_dev_verdict_leaf_root(&leaf, derived, why, sizeof(why)) &&
         memcmp(derived, l->root, 32) == 0 &&
         leaf.verdict == ZCL_DEV_VERDICT_LEAF_PASS &&
         zcl_dev_verdict_leaf_verify(&leaf, l->key, l->group, why,
                                     sizeof(why));
    if (ok) memcpy(wire, raw, ZCL_DEV_VERDICT_LEAF_WIRE_BYTES);
    free(raw);
    return ok;
}

static bool vm_root_known(const struct zcl_dev_vmmr_chain *c,
                          const uint8_t *batch, size_t n,
                          const uint8_t root[32])
{
    for (size_t i = 0; i < c->leaf_count; i++)
        if (memcmp(c->roots + i * 32u, root, 32) == 0) return true;
    for (size_t i = 0; i < n; i++)
        if (memcmp(batch + i * 32u, root, 32) == 0) return true;
    return false;
}

struct vm_adopt_ctx {
    const char *objects;
    const char *pair_store;
    const struct zcl_dev_vmmr_chain *chain;
    uint8_t *batch;
    size_t n;
    struct zcl_dev_vmmr_adopt *res;
};

static void vm_adopt_line(struct vm_adopt_ctx *c, const struct vm_line *l)
{
    uint8_t wire[ZCL_DEV_VERDICT_LEAF_WIRE_BYTES];
    c->res->seen++;
    if (!vm_leaf_load(c->pair_store, l, wire) ||
        !vcs_object_put_addressed(c->objects, l->root, wire, sizeof(wire))) {
        c->res->refused++;
        return;
    }
    if (vm_root_known(c->chain, c->batch, c->n, l->root)) return;
    memcpy(c->batch + c->n * 32u, l->root, 32);
    c->n++;
}

/* Append the adopted batch (when any) and report the chain a reader sees. */
static bool vm_adopt_finish(const char *dir, struct vm_adopt_ctx *c,
                            struct zcl_dev_vmmr_adopt *out,
                            char *why, size_t why_len)
{
    struct zcl_dev_vmmr_chain after;
    bool ok;
    if (c->n == 0)
        ok = zcl_dev_vmmr_load(dir, &after, why, why_len);
    else
        ok = zcl_dev_vmmr_append(dir, (const uint8_t (*)[32])c->batch, c->n,
                                 platform_time_wall_unix(), &after, why,
                                 why_len);
    free(c->batch);
    c->batch = NULL;
    if (!ok) return false;
    out->leaf_count = after.leaf_count;
    memcpy(out->head_root, after.head_root, 32);
    zcl_dev_vmmr_release(&after);
    return true;
}

static void vm_adopt_scan(struct vm_adopt_ctx *c, const char *log,
                          size_t log_len)
{
    size_t i = 0;
    while (i < log_len && c->n < ZCL_DEV_VMMR_MAX_LEAVES) {
        const char *eol = memchr(log + i, '\n', log_len - i);
        size_t n = eol ? (size_t)(eol - (log + i)) : log_len - i;
        struct vm_line l;
        if (vm_parse_line(log + i, n, &l)) vm_adopt_line(c, &l);
        i += n + 1;
    }
}

bool zcl_dev_vmmr_adopt_log(const char *dir, const char *pair_store,
                            const char *log, size_t log_len,
                            struct zcl_dev_vmmr_adopt *out,
                            char *why, size_t why_len)
{
    struct zcl_dev_vmmr_chain chain;
    char objects[PATH_MAX];
    struct vm_adopt_ctx c = {0};

    if (!out || !log || !pair_store || !vm_path(dir, "objects", objects,
                                                sizeof(objects)))
        return vm_fail(why, why_len, "verdict_mmr_arguments");
    memset(out, 0, sizeof(*out));
    if (!platform_directory_ensure(dir, 0700) ||
        !platform_directory_ensure(objects, 0700) ||
        !vcs_object_store_init(objects))
        return vm_fail(why, why_len, "verdict_mmr_dir");
    if (!zcl_dev_vmmr_load(dir, &chain, why, why_len)) return false;
    c.batch = zcl_malloc(ZCL_DEV_VMMR_MAX_LEAVES * 32u, "vmmr_adopt_batch");
    if (!c.batch) {
        zcl_dev_vmmr_release(&chain);
        return vm_fail(why, why_len, "verdict_mmr_alloc");
    }
    c.objects = objects;
    c.pair_store = pair_store;
    c.chain = &chain;
    c.res = out;
    vm_adopt_scan(&c, log, log_len);
    out->adopted = (uint32_t)c.n;
    zcl_dev_vmmr_release(&chain);
    return vm_adopt_finish(dir, &c, out, why, why_len);
}

/* ── Trust root ─────────────────────────────────────────────────────────── */

bool zcl_dev_vmmr_trust_load(struct zcl_dev_vmmr_trust *out,
                             char *why, size_t why_len)
{
    struct zcl_verify_attest_box_key box = {0};
    struct zcl_verify_attest_trust_root root;
    const char *w = NULL;
    if (out) memset(out, 0, sizeof(*out));
    box.known = out && zcl_dev_proof_signer_public(box.pubkey, &box.present,
                                                   &w);
    if (!box.known ||
        !zcl_verify_attest_trust_root_load(NULL, &box, &root, &w))
        return vm_fail(why, why_len, ZCL_DEV_VMMR_UNQUALIFIED);
    memcpy(out->verifier, root.verifier_pubkey, 32);
    memcpy(out->box, box.pubkey, 32);
    out->box_present = box.present;
    return true;
}

/* ── Admission ──────────────────────────────────────────────────────────── */

struct vm_entry {
    uint8_t root[32];
    struct zcl_dev_verdict_leaf_v1 leaf;
    bool eligible;
};
struct zcl_dev_vmmr_index {
    char objects[PATH_MAX];
    struct zcl_dev_vmmr_trust trust;
    struct vm_entry *entries;
    size_t count;
};

static bool vm_entry_load(const char *objects, const uint8_t root[32],
                          struct vm_entry *e)
{
    uint8_t *raw = NULL, derived[32];
    size_t len = 0;
    char why[80];
    bool ok;
    if (vcs_object_load_raw_bounded(objects, root,
                                    ZCL_DEV_VERDICT_LEAF_WIRE_BYTES, &raw,
                                    &len) != 0)
        return false;
    ok = zcl_dev_verdict_leaf_parse(raw, len, &e->leaf, why, sizeof(why)) &&
         zcl_dev_verdict_leaf_root(&e->leaf, derived, why, sizeof(why)) &&
         memcmp(derived, root, 32) == 0;
    free(raw);
    if (!ok) return false;
    memcpy(e->root, root, 32);
    e->eligible = zcl_dev_verdict_leaf_verify(&e->leaf, e->leaf.key,
                                              e->leaf.group, why,
                                              sizeof(why));
    return true;
}

struct zcl_dev_vmmr_index *zcl_dev_vmmr_index_open(
    const char *dir, const struct zcl_dev_vmmr_chain *chain,
    const struct zcl_dev_vmmr_trust *trust, char *why, size_t why_len)
{
    struct zcl_dev_vmmr_index *ix;
    char probe[PATH_MAX];
    if (!chain || !trust ||
        !vm_path(dir, "objects", probe, sizeof(probe))) {
        (void)vm_fail(why, why_len, "verdict_mmr_arguments");
        return NULL;
    }
    ix = zcl_calloc(1, sizeof(*ix), "vmmr_index");
    if (!ix) return NULL;
    (void)vm_path(dir, "objects", ix->objects, sizeof(ix->objects));
    ix->trust = *trust;
    ix->entries = zcl_calloc(chain->leaf_count ? chain->leaf_count : 1u,
                             sizeof(*ix->entries), "vmmr_index_entries");
    if (!ix->entries) {
        free(ix);
        return NULL;
    }
    for (size_t i = 0; i < chain->leaf_count; i++) {
        if (!vm_entry_load(ix->objects, chain->roots + i * 32u,
                           &ix->entries[i])) {
            (void)vm_fail(why, why_len, "verdict_mmr_leaf_unreadable");
            zcl_dev_vmmr_index_close(ix);
            return NULL;
        }
        ix->count++;
    }
    return ix;
}

void zcl_dev_vmmr_index_close(struct zcl_dev_vmmr_index *ix)
{
    if (!ix) return;
    free(ix->entries);
    free(ix);
}

enum zcl_dev_observation_verdict zcl_dev_vmmr_admit(
    const struct zcl_dev_vmmr_index *ix,
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], const char *group,
    uint64_t *elapsed_ms, char *why, size_t why_len)
{
    uint8_t (*roots)[32];
    size_t n = 0;
    enum zcl_dev_observation_verdict v;
    if (elapsed_ms) *elapsed_ms = 0;
    if (!ix || !key || !group) {
        (void)vm_fail(why, why_len, "verdict_mmr_arguments");
        return ZCL_DEV_OBSERVATION_MISSING;
    }
    roots = zcl_malloc((ix->count ? ix->count : 1u) * 32u, "vmmr_admit_roots");
    if (!roots) return ZCL_DEV_OBSERVATION_MISSING;
    for (size_t i = 0; i < ix->count; i++)
        if (memcmp(ix->entries[i].leaf.key, key, 32) == 0)
            memcpy(roots[n++], ix->entries[i].root, 32);
    if (n == 0) {
        free(roots);
        (void)vm_fail(why, why_len, "proof_observation_missing");
        return ZCL_DEV_OBSERVATION_MISSING;
    }
    v = zcl_dev_observation_admit(ix->objects, key, group,
                                  (const uint8_t (*)[32])roots, n, NULL, why,
                                  why_len);
    free(roots);
    if (v == ZCL_DEV_OBSERVATION_PASS) {
        /* A valid local prefix cannot prove that a later FAIL was retained. */
        (void)vm_fail(why, why_len, ZCL_DEV_VMMR_UNQUALIFIED);
        return ZCL_DEV_OBSERVATION_MISSING;
    }
    return v;
}

/* ── Sampling and divergence ────────────────────────────────────────────── */

bool zcl_dev_vmmr_sampled(const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES],
                          const char *pair)
{
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    if (!key || !pair) return true; /* unknown pair: run it cold */
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)VM_SAMPLE_DOMAIN,
                   sizeof(VM_SAMPLE_DOMAIN) - 1u);
    sha3_256_write(&sha, key, ZCL_DEV_VERDICT_LEAF_KEY_BYTES);
    sha3_256_write(&sha, (const uint8_t *)pair, strlen(pair));
    sha3_256_finalize(&sha, digest);
    return (digest[0] & ZCL_DEV_VMMR_SAMPLE_MASK) == 0;
}

void zcl_dev_vmmr_resolve(const struct zcl_dev_vmmr_item *items, size_t count,
                          bool *skip, struct zcl_dev_vmmr_plan *plan)
{
    memset(plan, 0, sizeof(*plan));
    for (size_t i = 0; i < count; i++) {
        bool pass = items[i].admitted == ZCL_DEV_OBSERVATION_PASS;
        skip[i] = pass && !items[i].sampled;
        if (pass && items[i].sampled) {
            plan->sampled++;
            if (!items[i].cold_pass) plan->divergence = true;
        }
        if (skip[i]) {
            plan->reused++;
            plan->saved_ms += items[i].elapsed_ms;
        }
    }
    if (!plan->divergence) return;
    for (size_t i = 0; i < count; i++) skip[i] = false;
    plan->reused = 0;
    plan->saved_ms = 0;
}
