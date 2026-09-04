/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fold one unit of work's declared inputs into a single closure digest.
 *
 * The interesting property is what this file does NOT do: for a declared
 * directory it reads no file bytes at all. codeindex_merkle already carries a
 * digest for every directory that holds an indexed file, and that digest
 * already binds every file below it, recursively. So a unit keyed on
 * engine/services/src costs one array lookup, and a commit that touches only
 * contexts/wallet provably cannot move it.
 *
 * Only ci_closure_add_raw() reads anything, and it exists because the indexed
 * tree is .c/.h only: shell scripts, Makefiles, baselines and documents have to
 * be hashed the slow way or not covered at all, and "not covered" is how a
 * receipt starts admitting a unit over a violation.
 */

#include "codeindex/codeindex_closure.h"

#include "crypto/sha3.h"
#include "platform/positioned_file.h"

#include <string.h>

static const uint8_t CLOSURE_TAG = 0x12; /* 0x10/0x11 are the Merkle leaf/node */


bool ci_closure_init(struct ci_closure *c, const char *domain)
{
    if (!c || !domain || !domain[0]) return false;
    size_t n = strlen(domain);
    if (n >= sizeof(c->domain)) return false;
    memset(c, 0, sizeof(*c));
    memcpy(c->domain, domain, n + 1);
    return true;
}

/* Reserve the next slot, or poison the closure. A refused add must not leave a
 * closure that seals: silently dropping an input is exactly the failure this
 * whole mechanism exists to prevent. */
static bool closure_slot(struct ci_closure *c, const char *path, size_t *out)
{
    if (!c) return false;
    if (!path || !path[0] || strlen(path) >= CI_CLOSURE_PATH_MAX) {
        c->poisoned = true;
        return false;
    }
    if (c->nentries >= CI_CLOSURE_MAX_ENTRIES) {
        c->poisoned = true;
        return false;
    }
    for (uint32_t i = 0; i < c->nentries; i++) {
        if (strcmp(c->entry[i].path, path) == 0) {
            /* A caller that declares the same input twice does not know its
             * own closure. Refuse rather than dedupe: deduping hides the
             * confusion, and the next mistake it makes will be a missing
             * input, not a doubled one. */
            c->poisoned = true;
            return false;
        }
    }
    *out = c->nentries++;
    return true;
}

/* "", ".", "/" all mean the whole indexed tree, matching ci_merkle_node(). The
 * stored path is normalized so two spellings of the root cannot both be
 * declared and both be accepted. */
static const char *closure_dir_canonical(const char *dirpath)
{
    if (!dirpath) return NULL;
    if (dirpath[0] == 0) return "";
    if (strcmp(dirpath, ".") == 0 || strcmp(dirpath, "/") == 0) return "";
    return dirpath;
}

bool ci_closure_add_dir(struct ci_closure *c, const struct ci_merkle *m,
                        const char *dirpath)
{
    if (!c || !m) { if (c) c->poisoned = true; return false; }
    const char *canonical = closure_dir_canonical(dirpath);
    if (!canonical) { c->poisoned = true; return false; }

    struct ci_merkle_node node;
    bool found = false;
    if (!ci_merkle_node(m, canonical, &node, &found) || !found) {
        /* An input that is not in the tree means the closure is not the one
         * the caller declared. Never a digest over nothing. */
        c->poisoned = true;
        return false;
    }
    /* The root's canonical stored path is "" and closure_slot() refuses an
     * empty path, so the root is stored under a name no relative path can
     * collide with. */
    const char *stored = canonical[0] ? canonical : "/";
    size_t slot = 0;
    if (!closure_slot(c, stored, &slot)) return false;
    memcpy(c->entry[slot].path, stored, strlen(stored) + 1);
    c->entry[slot].source = (uint8_t)CI_CLOSURE_TREE_DIR;
    c->entry[slot].digest = node.digest;
    c->cost.dir_entries++;
    c->cost.files_covered += node.file_count;
    c->cost.bytes_covered += node.total_bytes;
    return true;
}

bool ci_closure_add_file(struct ci_closure *c, const struct ci_merkle *m,
                         const char *filepath)
{
    if (!c || !m) { if (c) c->poisoned = true; return false; }
    struct ci_merkle_leaf leaf;
    bool found = false;
    if (!ci_merkle_leaf(m, filepath ? filepath : "", &leaf, &found) || !found) {
        c->poisoned = true;
        return false;
    }
    size_t slot = 0;
    if (!closure_slot(c, filepath, &slot)) return false;
    memcpy(c->entry[slot].path, filepath, strlen(filepath) + 1);
    c->entry[slot].source = (uint8_t)CI_CLOSURE_TREE_FILE;
    c->entry[slot].digest = leaf.digest;
    c->cost.file_entries++;
    c->cost.files_covered += 1;
    c->cost.bytes_covered += leaf.size;
    return true;
}

/* The one path that reads bytes. Domain-separated from the Merkle leaf so a
 * raw digest can never be confused with an indexed one even when both name the
 * same file. */
static bool closure_raw_digest(const char *root, const char *relpath,
                               struct zcl_sha3_digest *out, uint64_t *out_bytes)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open_beneath(&file, root, relpath))
        return false;
    if (!platform_positioned_file_snapshot(&file, &before)) {
        platform_positioned_file_close(&file);
        return false;
    }
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = "zcl.codeindex.closure.raw.v1";
    sha3_256_write(&sha, &CLOSURE_TAG, 1);
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&sha, (const unsigned char *)relpath, strlen(relpath) + 1);
    unsigned char size_wire[8];
    for (unsigned i = 0; i < 8; i++)
        size_wire[i] = (unsigned char)((before.size >> (i * 8)) & 0xffU);
    sha3_256_write(&sha, size_wire, sizeof(size_wire));

    unsigned char buf[64 * 1024];
    uint64_t total = 0;
    bool ok = true;
    while (total < before.size) {
        size_t want = before.size - total < sizeof(buf)
                          ? (size_t)(before.size - total) : sizeof(buf);
        int64_t got = platform_positioned_file_read(&file, buf, want, total);
        if (got < 0) { ok = false; break; }
        if (got == 0) break;
        sha3_256_write(&sha, buf, (size_t)got);
        total += (uint64_t)got;
    }
    /* Same before/after rule the Merkle leaf uses: bytes that moved under the
     * read are not a digest, they are a race. */
    if (ok && (!platform_positioned_file_snapshot(&file, &after) ||
               total != before.size || before.size != after.size ||
               before.modified_seconds != after.modified_seconds ||
               before.modified_nanoseconds != after.modified_nanoseconds))
        ok = false;
    platform_positioned_file_close(&file);
    if (!ok) return false;
    sha3_256_finalize(&sha, out->bytes);
    *out_bytes = total;
    return true;
}

bool ci_closure_add_raw(struct ci_closure *c, const char *root,
                        const char *relpath)
{
    if (!c || !root || !relpath) { if (c) c->poisoned = true; return false; }
    struct zcl_sha3_digest digest;
    uint64_t bytes = 0;
    if (!closure_raw_digest(root, relpath, &digest, &bytes)) {
        c->poisoned = true;
        return false;
    }
    size_t slot = 0;
    if (!closure_slot(c, relpath, &slot)) return false;
    memcpy(c->entry[slot].path, relpath, strlen(relpath) + 1);
    c->entry[slot].source = (uint8_t)CI_CLOSURE_RAW_FILE;
    c->entry[slot].digest = digest;
    c->cost.raw_entries++;
    c->cost.bytes_hashed += bytes;
    return true;
}

bool ci_closure_seal(const struct ci_closure *c, struct zcl_sha3_digest *out)
{
    if (!c || !out || c->poisoned || c->nentries == 0) return false;

    /* Sort a copy of the index, not the caller's closure: seal is a read. */
    uint16_t order[CI_CLOSURE_MAX_ENTRIES];
    for (uint32_t i = 0; i < c->nentries; i++) order[i] = (uint16_t)i;
    /* Insertion sort — nentries is capped at 256 and this keeps the comparison
     * rule visible in one place instead of behind a callback. */
    for (uint32_t i = 1; i < c->nentries; i++) {
        uint16_t key = order[i];
        uint32_t j = i;
        while (j > 0 && strcmp(c->entry[order[j - 1]].path,
                               c->entry[key].path) > 0) {
            order[j] = order[j - 1];
            j--;
        }
        order[j] = key;
    }

    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = "zcl.codeindex.closure.v1";
    sha3_256_write(&sha, &CLOSURE_TAG, 1);
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&sha, (const unsigned char *)c->domain,
                   strlen(c->domain) + 1);
    unsigned char count_wire[4];
    for (unsigned i = 0; i < 4; i++)
        count_wire[i] = (unsigned char)((c->nentries >> (i * 8)) & 0xffU);
    sha3_256_write(&sha, count_wire, sizeof(count_wire));
    for (uint32_t i = 0; i < c->nentries; i++) {
        const uint16_t k = order[i];
        sha3_256_write(&sha, &c->entry[k].source, 1);
        sha3_256_write(&sha, (const unsigned char *)c->entry[k].path,
                       strlen(c->entry[k].path) + 1);
        sha3_256_write(&sha, c->entry[k].digest.bytes, 32);
    }
    sha3_256_finalize(&sha, out->bytes);
    return true;
}

void ci_closure_cost(const struct ci_closure *c, struct ci_closure_cost *out)
{
    if (!out) return;
    if (!c) { memset(out, 0, sizeof(*out)); return; }
    *out = c->cost;
    out->entries = c->nentries;
}
