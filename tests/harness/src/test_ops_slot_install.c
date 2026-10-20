/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_ops_slot_install - `ops slot install` and the owner-key pins on
 * `zcode release verify` (tools/command/native_ops_slot_install.c,
 * tools/command/release_pin.c).
 *
 * The property under test: a binary becomes a slot ONLY when its release is
 * signed by a key the receiver pinned and the bytes match the package
 * manifest exactly, and every refusal leaves the slots directory untouched.
 *
 *   a. pinned + matching: installs, mode 0755, identical bytes, no tmp left
 *   b. unpinned signer: RELEASE_UNPINNED, nothing written (and PIN_REQUIRED
 *      when no pin is given at all: there is no unpinned install)
 *   c. one flipped byte in `from`: BINARY_DIGEST_MISMATCH, nothing written
 *   d. the wrong package root: RELEASE_ROOT_MISMATCH
 *   e. identical re-install is an idempotent ok; different bytes under the
 *      same name give SLOT_EXISTS_DIFFERENT and leave the slot unchanged
 *   f. bad names ("../x", "-x", 65 characters) are refused
 *   g. dry_run performs every check and writes nothing
 *   i. a tampered or unsigned release doc is refused; j. a symlinked slot
 *      path is SLOT_PATH_UNSAFE and nothing is written through it
 *   k. ZRS1 v2 hybrid releases and pair pins (docs/work/PQ_HYBRID_RELEASE_
 *      SIGNATURE.md 6.1): a pair pin plus a v2 doc installs; a different pinned
 *      SLH-DSA key is PQ_KEY_MISMATCH; an Ed25519-only pin is
 *      RELEASE_PQ_UNPINNED; a v1 doc passes a pair pin until require_pq
 *      (RELEASE_PQ_REQUIRED); malformed pair lines name their line number
 *   h. `zcode release verify` without pin is unchanged; with pin/pin_file/
 *      package_root it gains the same typed refusals
 *
 * Hermetic: per-pid ./test-tmp directory, fixture seed keys, no network, no
 * chain, no home directory (ZCL_BINARY_SLOTS_DIR points into the temp dir).
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_slot_common.h"

#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "vcs/package_content.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"
#include "zid/zid.h"
#include "zid/zid_hybrid.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OSI_BYTES (VCS_PACKAGE_CHUNK_BYTES + 17u) /* two chunks */

struct osi_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

struct osi_pkg {
    char root_hex[65];
    char from[PATH_MAX];
    char doc[PATH_MAX];
    uint8_t *bytes;
    uint8_t pubkey[32];
};

struct osi_fx {
    char dir[PATH_MAX];
    char data[PATH_MAX];
    char slots[PATH_MAX];
    char pins_ok[PATH_MAX];
    char pins_other[PATH_MAX];
    char pubkey_hex[65];
    char other_hex[65];
};

static void oc_init(struct osi_cmd *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.ops_slot_install_test.v1");
}

static void oc_free(struct osi_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool oc_ok(const struct osi_cmd *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED &&
           c->reply.exit_code == ZCL_COMMAND_EXIT_OK;
}

static bool oc_code(const struct osi_cmd *c, const char *code)
{
    return strcmp(c->reply.error.code, code) == 0;
}

static const char *oc_str(const struct osi_cmd *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
}

static int oc_bool(const struct osi_cmd *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    if (!v || v->type != JSON_BOOL)
        return -1;
    return json_get_bool(v) ? 1 : 0;
}

static bool osi_write_file(const char *path, const void *data, size_t len,
                           mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return false;
    bool ok = write(fd, data, len) == (ssize_t)len;
    close(fd);
    return ok && chmod(path, mode) == 0;
}

static uint8_t *osi_read_file(const char *path, size_t *len)
{
    struct stat sb;
    int fd = open(path, O_RDONLY);
    uint8_t *buf = NULL;
    if (fd < 0)
        return NULL;
    if (fstat(fd, &sb) == 0 && sb.st_size >= 0) {
        buf = malloc((size_t)sb.st_size + 1u); // raw-alloc-ok:test-fixture
        if (buf && read(fd, buf, (size_t)sb.st_size) != sb.st_size) {
            free(buf); // raw-alloc-ok:test-fixture
            buf = NULL;
        }
        *len = (size_t)sb.st_size;
    }
    close(fd);
    return buf;
}

/* Number of entries in a directory, or -1 if it does not exist. */
static int osi_count(const char *path)
{
    DIR *d = opendir(path);
    int n = 0;
    if (!d)
        return -1;
    for (struct dirent *e = readdir(d); e; e = readdir(d))
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            n++;
    closedir(d);
    return n;
}

static void osi_rm_tree(const char *path)
{
    char rm[PATH_MAX + 16];
    snprintf(rm, sizeof(rm), "rm -rf '%s'", path);
    TEST_DISCARD(system(rm));
}

static bool osi_fx_init(struct osi_fx *fx)
{
    char cwd[PATH_MAX];
    memset(fx, 0, sizeof(*fx));
    if (!getcwd(cwd, sizeof(cwd)))
        return false;
    snprintf(fx->dir, sizeof(fx->dir), "%s/test-tmp/%d_osi", cwd,
             (int)getpid());
    osi_rm_tree(fx->dir);
    snprintf(fx->data, sizeof(fx->data), "%s/data", fx->dir);
    snprintf(fx->slots, sizeof(fx->slots), "%s/slots", fx->dir);
    snprintf(fx->pins_ok, sizeof(fx->pins_ok), "%s/pins_ok", fx->dir);
    snprintf(fx->pins_other, sizeof(fx->pins_other), "%s/pins_other", fx->dir);
    mkdir("./test-tmp", 0755);
    if (mkdir(fx->dir, 0755) != 0 || mkdir(fx->data, 0755) != 0)
        return false;
    setenv("ZCL_BINARY_SLOTS_DIR", fx->slots, 1);
    return true;
}

static void osi_seed_key(uint8_t fill, uint8_t pubkey[32])
{
    struct zid_doc doc;
    struct zid_release rel;
    uint8_t seed[32];
    memset(seed, fill, sizeof(seed));
    memset(&rel, 0, sizeof(rel));
    snprintf(rel.name, sizeof(rel.name), "key");
    snprintf(rel.version, sizeof(rel.version), "0");
    zid_release_sign(&doc, &rel, 1, 4102444800ULL, seed);
    memcpy(pubkey, doc.master_pubkey, 32);
}

static bool osi_write_pins(struct osi_fx *fx)
{
    uint8_t ok[32], other[32];
    char text[256];
    osi_seed_key(0x5A, ok);
    osi_seed_key(0x6B, other);
    HexStr(ok, 32, false, fx->pubkey_hex, sizeof(fx->pubkey_hex));
    HexStr(other, 32, false, fx->other_hex, sizeof(fx->other_hex));
    snprintf(text, sizeof(text), "# fleet owner\n\n  %s  \n", fx->pubkey_hex);
    if (!osi_write_file(fx->pins_ok, text, strlen(text), 0600))
        return false;
    snprintf(text, sizeof(text), "%s\n", fx->other_hex);
    return osi_write_file(fx->pins_other, text, strlen(text), 0600);
}

/* Build one signed package in the store: a two-chunk "z23" binary of a given
 * fill, its manifest and chunks, a checked-out copy, and the signed doc. */
static bool osi_make_pkg(const struct osi_fx *fx, struct osi_pkg *p,
                         const char *tag, uint8_t fill)
{
    struct vcs_package_manifest m;
    uint8_t *wire = NULL, root[32], seed[32];
    size_t wire_len = 0;
    struct zid_doc doc;
    struct zid_release rel;
    uint8_t docwire[ZID_DOC_MAX];
    char hex[ZID_DOC_MAX * 2 + 1], dir[PATH_MAX];
    memset(p, 0, sizeof(*p));
    p->bytes = malloc(OSI_BYTES); // raw-alloc-ok:test-fixture
    if (!p->bytes)
        return false;
    for (size_t i = 0; i < OSI_BYTES; i++)
        p->bytes[i] = (uint8_t)(fill + i * 31u);
    vcs_package_manifest_init(&m);
    bool ok = vcs_package_content_add_file(&m, "z23",
                                           VCS_PACKAGE_MODE_EXECUTABLE,
                                           p->bytes, OSI_BYTES) &&
              vcs_package_manifest_serialize(&m, &wire, &wire_len);
    struct vcs_package_store *store = ok
        ? vcs_package_store_open(fx->data, vcs_package_store_quota_bytes())
        : NULL;
    ok = store &&
         vcs_package_store_put_manifest(store, wire, wire_len, root) ==
             VCS_PACKAGE_STORE_OK &&
         vcs_package_content_put_file(store, root, "z23", p->bytes,
                                      OSI_BYTES) == VCS_PACKAGE_STORE_OK;
    if (store)
        vcs_package_store_close(store);
    free(wire);
    vcs_package_manifest_free(&m);
    if (!ok)
        return false;
    HexStr(root, 32, false, p->root_hex, sizeof(p->root_hex));
    snprintf(dir, sizeof(dir), "%s/from_%s", fx->dir, tag);
    snprintf(p->from, sizeof(p->from), "%s/z23", dir);
    snprintf(p->doc, sizeof(p->doc), "%s/release_%s.zid", fx->dir, tag);
    memset(seed, 0x5A, sizeof(seed));
    memset(&rel, 0, sizeof(rel));
    snprintf(rel.name, sizeof(rel.name), "z23");
    snprintf(rel.version, sizeof(rel.version), "1.0.%s", tag);
    memcpy(rel.manifest_root, root, 32);
    if (!zid_release_sign(&doc, &rel, 1,
                          (uint64_t)platform_time_wall_unix() + 86400u, seed))
        return false;
    size_t n = zid_doc_encode(docwire, sizeof(docwire), &doc);
    HexStr(docwire, n, false, hex, sizeof(hex));
    memcpy(p->pubkey, doc.master_pubkey, 32);
    return n > 0 && mkdir(dir, 0755) == 0 &&
           osi_write_file(p->from, p->bytes, OSI_BYTES, 0644) &&
           osi_write_file(p->doc, hex, strlen(hex), 0644);
}

static void osi_pkg_free(struct osi_pkg *p)
{
    free(p->bytes);
    p->bytes = NULL;
}

struct osi_req {
    const char *release, *from, *name, *root, *pin, *pin_file, *cosigs;
    bool dry_run, require_pq;
};

static void osi_run(const struct osi_fx *fx, const struct osi_req *r,
                    struct osi_cmd *c)
{
    oc_init(c);
    json_push_kv_str(&c->input, "release", r->release);
    json_push_kv_str(&c->input, "from", r->from);
    json_push_kv_str(&c->input, "name", r->name);
    json_push_kv_str(&c->input, "package_root", r->root);
    json_push_kv_str(&c->input, "datadir", fx->data);
    if (r->pin)
        json_push_kv_str(&c->input, "pin", r->pin);
    if (r->pin_file)
        json_push_kv_str(&c->input, "pin_file", r->pin_file);
    if (r->cosigs)
        json_push_kv_str(&c->input, "cosigs", r->cosigs);
    if (r->require_pq)
        json_push_kv_bool(&c->input, "require_pq", true);
    if (r->dry_run)
        json_push_kv_bool(&c->input, "dry_run", true);
    zcl_native_handle_ops_slot_install(&c->request, &c->reply);
}

static int osi_check(bool ok, const char *what)
{
    printf("ops_slot_install: %s... %s\n", what, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static struct osi_req osi_good(const struct osi_fx *fx, const struct osi_pkg *p,
                               const char *name)
{
    struct osi_req r = { .release = p->doc, .from = p->from, .name = name,
                         .root = p->root_hex, .pin_file = fx->pins_ok };
    return r;
}

static void osi_print_reply(const struct osi_cmd *c)
{
    const char *slot = oc_str(c, "slot"), *sha = oc_str(c, "sha256");
    const char *signer = oc_str(c, "signer");
    printf("  reply: slot=%s sha256=%s size=%lld signer=%s installed=%d\n",
           slot ? slot : "?", sha ? sha : "?",
           (long long)json_get_int(json_get(&c->reply.data, "size")),
           signer ? signer : "?", oc_bool(c, "installed"));
}

/* A group-writable slot dir or a world-writable slots root fails verify. */
static int test_osi_writable(const struct osi_fx *fx, const char *tmp)
{
    struct stat rs, ds;
    int failures = 0;
    bool have = stat(fx->slots, &rs) == 0 && stat(tmp, &ds) == 0;
    failures += osi_check(have && chmod(tmp, 0775) == 0 &&
                              slot_verify_installed(tmp) ==
                                  SLOT_VERIFY_WRITABLE,
                          "a group-writable slot dir fails verify");
    TEST_DISCARD(chmod(tmp, ds.st_mode & 07777));
    failures += osi_check(have && chmod(fx->slots, 0777) == 0 &&
                              slot_verify_installed(tmp) ==
                                  SLOT_VERIFY_WRITABLE,
                          "a world-writable slots root fails verify");
    TEST_DISCARD(chmod(fx->slots, rs.st_mode & 07777));
    failures += osi_check(slot_verify_installed(tmp) == SLOT_VERIFY_OK,
                          "verify passes again once the modes are tight");
    return failures;
}

/* a. pinned + matching */
static int test_osi_install(const struct osi_fx *fx, const struct osi_pkg *p)
{
    struct osi_cmd c;
    struct osi_req r = osi_good(fx, p, "fleet-1.0");
    char path[PATH_MAX], tmp[PATH_MAX];
    struct stat sb;
    size_t len = 0;
    int failures = 0;
    osi_run(fx, &r, &c);
    osi_print_reply(&c);
    failures += osi_check(oc_ok(&c) && oc_bool(&c, "installed") == 1 &&
                          oc_bool(&c, "idempotent") == 0 &&
                          oc_str(&c, "slot") &&
                          strcmp(oc_str(&c, "slot"), "fleet-1.0/z23") == 0 &&
                          oc_str(&c, "sha256") && oc_str(&c, "signer") &&
                          strlen(oc_str(&c, "signer")) == 16,
                      "a pinned, matching release installs");
    snprintf(path, sizeof(path), "%s/fleet-1.0/z23", fx->slots);
    uint8_t *got = osi_read_file(path, &len);
    failures += osi_check(got && len == OSI_BYTES &&
                          memcmp(got, p->bytes, OSI_BYTES) == 0 &&
                          stat(path, &sb) == 0 &&
                          (sb.st_mode & 07777) == 0755,
                      "the slot is byte-identical and mode 0755");
    free(got);
    snprintf(tmp, sizeof(tmp), "%s/fleet-1.0", fx->slots);
    failures += osi_check(osi_count(fx->slots) == 1 && osi_count(tmp) == 2 &&
                          slot_verify_installed(tmp) == SLOT_VERIFY_OK,
                          "only the binary and its digest record exist, "
                          "and they agree");
    failures += test_osi_writable(fx, tmp);
    oc_free(&c);
    return failures;
}

/* b. unpinned signer, no pin at all */
static int test_osi_unpinned(const struct osi_fx *fx, const struct osi_pkg *p)
{
    struct osi_cmd c;
    struct osi_req r = osi_good(fx, p, "unpinned");
    int failures = 0;
    r.pin_file = fx->pins_other;
    osi_run(fx, &r, &c);
    printf("  refusal: %s: %s\n", c.reply.error.code, c.reply.error.message);
    failures += osi_check(!oc_ok(&c) && oc_code(&c, "RELEASE_UNPINNED") &&
                          osi_count(fx->slots) == 1,
                      "an unpinned signer is RELEASE_UNPINNED, nothing written");
    oc_free(&c);
    r.pin_file = NULL;
    r.pin = fx->other_hex;
    osi_run(fx, &r, &c);
    failures += osi_check(oc_code(&c, "RELEASE_UNPINNED"),
                          "an inline pin of another key is unpinned too");
    oc_free(&c);
    r.pin = NULL;
    osi_run(fx, &r, &c);
    failures += osi_check(oc_code(&c, "PIN_REQUIRED") && osi_count(fx->slots) == 1,
                          "no pin at all is PIN_REQUIRED");
    oc_free(&c);
    r.pin_file = "/nonexistent/pins";
    osi_run(fx, &r, &c);
    failures += osi_check(oc_code(&c, "PIN_FILE_UNREADABLE"),
                          "an unreadable pin file is a typed refusal");
    oc_free(&c);
    return failures;
}

/* c. tampered byte, d. wrong root */
static int test_osi_tamper_root(const struct osi_fx *fx,
                                const struct osi_pkg *p,
                                const struct osi_pkg *other)
{
    struct osi_cmd c;
    struct osi_req r = osi_good(fx, p, "tampered");
    char bad[PATH_MAX];
    int failures = 0;
    snprintf(bad, sizeof(bad), "%s/tampered.bin", fx->dir);
    p->bytes[OSI_BYTES - 5] ^= 0x01;
    bool wrote = osi_write_file(bad, p->bytes, OSI_BYTES, 0644);
    p->bytes[OSI_BYTES - 5] ^= 0x01;
    r.from = bad;
    osi_run(fx, &r, &c);
    failures += osi_check(wrote && !oc_ok(&c) &&
                          oc_code(&c, "BINARY_DIGEST_MISMATCH") &&
                          osi_count(fx->slots) == 1,
                      "a tampered byte is BINARY_DIGEST_MISMATCH, nothing "
                      "written");
    oc_free(&c);
    r = osi_good(fx, p, "wrongroot");
    r.root = other->root_hex;
    osi_run(fx, &r, &c);
    failures += osi_check(oc_code(&c, "RELEASE_ROOT_MISMATCH") &&
                          osi_count(fx->slots) == 1,
                      "a wrong package root is RELEASE_ROOT_MISMATCH");
    oc_free(&c);
    return failures;
}

/* e. idempotence and SLOT_EXISTS_DIFFERENT */
static int test_osi_idempotent(const struct osi_fx *fx,
                               const struct osi_pkg *p,
                               const struct osi_pkg *other)
{
    struct osi_cmd c;
    struct osi_req r = osi_good(fx, p, "fleet-1.0");
    char path[PATH_MAX];
    size_t len = 0;
    int failures = 0;
    osi_run(fx, &r, &c);
    failures += osi_check(oc_ok(&c) && oc_bool(&c, "idempotent") == 1 &&
                          oc_bool(&c, "installed") == 0,
                      "re-installing identical bytes is an idempotent ok");
    oc_free(&c);
    r = osi_good(fx, other, "fleet-1.0");
    osi_run(fx, &r, &c);
    failures += osi_check(!oc_ok(&c) && oc_code(&c, "SLOT_EXISTS_DIFFERENT"),
                      "different bytes under the same name are refused");
    oc_free(&c);
    snprintf(path, sizeof(path), "%s/fleet-1.0/z23", fx->slots);
    uint8_t *got = osi_read_file(path, &len);
    failures += osi_check(got && len == OSI_BYTES &&
                          memcmp(got, p->bytes, OSI_BYTES) == 0 &&
                          osi_count(fx->slots) == 1,
                      "the existing slot is untouched");
    free(got);
    return failures;
}

/* f. names, g. dry run */
static int test_osi_names_dry(const struct osi_fx *fx, const struct osi_pkg *p)
{
    static const char *bad[] = { "../x", "-x", ".hidden", "a/b", "Up", "a.tmp.1",
                                 "" };
    char long_name[80];
    struct osi_cmd c;
    int failures = 0;
    memset(long_name, 'a', 65);
    long_name[65] = '\0';
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]) + 1u; i++) {
        struct osi_req r = osi_good(fx, p,
            i < sizeof(bad) / sizeof(bad[0]) ? bad[i] : long_name);
        osi_run(fx, &r, &c);
        failures += osi_check(!oc_ok(&c) && (oc_code(&c, "BAD_SLOT_NAME") ||
                                              oc_code(&c, "MISSING_INPUT")) &&
                              osi_count(fx->slots) == 1,
                          "a bad slot name is refused");
        oc_free(&c);
    }
    struct osi_req r = osi_good(fx, p, "dry-run");
    r.dry_run = true;
    osi_run(fx, &r, &c);
    failures += osi_check(oc_ok(&c) && oc_bool(&c, "dry_run") == 1 &&
                          oc_bool(&c, "installed") == 0 &&
                          osi_count(fx->slots) == 1,
                      "dry_run passes every check and writes nothing");
    oc_free(&c);
    return failures;
}

/* h. verify with and without pins */
static int test_osi_verify(const struct osi_fx *fx, const struct osi_pkg *p,
                           const struct osi_pkg *other)
{
    struct { const char *pin, *pin_file, *root; const char *want; } rows[] = {
        { NULL, NULL, NULL, NULL },
        { NULL, NULL, p->root_hex, NULL },
        { fx->pubkey_hex, NULL, NULL, NULL },
        { NULL, fx->pins_ok, p->root_hex, NULL },
        { fx->other_hex, NULL, NULL, "RELEASE_UNPINNED" },
        { NULL, fx->pins_other, NULL, "RELEASE_UNPINNED" },
        { NULL, NULL, other->root_hex, "RELEASE_ROOT_MISMATCH" },
        { "zz", NULL, NULL, "BAD_PIN" },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        struct osi_cmd c;
        oc_init(&c);
        json_push_kv_str(&c.input, "file", p->doc);
        if (rows[i].pin)
            json_push_kv_str(&c.input, "pin", rows[i].pin);
        if (rows[i].pin_file)
            json_push_kv_str(&c.input, "pin_file", rows[i].pin_file);
        if (rows[i].root)
            json_push_kv_str(&c.input, "package_root", rows[i].root);
        zcl_native_handle_zcode_release_verify(&c.request, &c.reply);
        bool good = rows[i].want ? (!oc_ok(&c) && oc_code(&c, rows[i].want))
                                 : (oc_ok(&c) && oc_bool(&c, "valid") == 1);
        failures += osi_check(good, "zcode release verify pin/root matrix row");
        oc_free(&c);
    }
    return failures;
}

/* i. a tampered or unsigned release doc, j. a slot path that is a symlink */
static int test_osi_doc_and_path(const struct osi_fx *fx,
                                 const struct osi_pkg *p)
{
    struct osi_cmd c;
    struct osi_req r = osi_good(fx, p, "baddoc");
    char bad[PATH_MAX], link[PATH_MAX], target[PATH_MAX];
    size_t len = 0;
    int failures = 0;
    uint8_t *doc = osi_read_file(p->doc, &len);
    snprintf(bad, sizeof(bad), "%s/release_tampered.zid", fx->dir);
    if (doc && len > 8) {
        doc[len - 3] = doc[len - 3] == '0' ? '1' : '0'; /* inside the signature */
        failures += osi_check(osi_write_file(bad, doc, len, 0644),
                              "tampered release doc fixture written");
    } else {
        failures += osi_check(false, "release doc fixture readable");
    }
    free(doc);
    r.release = bad;
    osi_run(fx, &r, &c);
    printf("  refusal: %s\n", c.reply.error.code);
    failures += osi_check(!oc_ok(&c) && oc_code(&c, "RELEASE_INVALID") &&
                          osi_count(fx->slots) == 1,
                      "a tampered signature is RELEASE_INVALID, nothing written");
    oc_free(&c);
    snprintf(bad, sizeof(bad), "%s/release_unsigned.zid", fx->dir);
    failures += osi_check(osi_write_file(bad, "00112233", 8, 0644),
                          "unsigned doc fixture written");
    r.release = bad;
    osi_run(fx, &r, &c);
    failures += osi_check(!oc_ok(&c) && osi_count(fx->slots) == 1,
                      "an unsigned release doc is refused, nothing written");
    oc_free(&c);
    snprintf(target, sizeof(target), "%s/escape_target", fx->dir);
    snprintf(link, sizeof(link), "%s/linked", fx->slots);
    failures += osi_check(mkdir(target, 0755) == 0 &&
                              symlink(target, link) == 0,
                          "symlink slot fixture");
    r = osi_good(fx, p, "linked");
    osi_run(fx, &r, &c);
    failures += osi_check(!oc_ok(&c) && oc_code(&c, "SLOT_PATH_UNSAFE") &&
                          osi_count(target) == 0,
                      "a symlinked slot path is SLOT_PATH_UNSAFE, no write "
                      "through it");
    oc_free(&c);
    return failures;
}

/* ── k. ZRS1 v2 hybrid releases and pair pins ───────────────────────── */

struct osi_hy {
    char doc_v2[PATH_MAX];       /* a v2 doc signed by the owner's pair */
    char pins_pair[PATH_MAX];    /* zrs1 pair of that owner + the signer pk */
    char pins_wrong_pq[PATH_MAX];/* same owner, a different SLH-DSA key */
    char pins_pair_rq[PATH_MAX]; /* the pair plus a require-pq directive */
    char pair_line[200];
    char wrong_line[200];
};

static void osi_pq_seed(uint8_t fill, uint8_t seed[ZRS1_PQ_SEED_SIZE])
{
    for (size_t i = 0; i < ZRS1_PQ_SEED_SIZE; i++)
        seed[i] = (uint8_t)(fill + i);
}

static bool osi_hy_init(const struct osi_fx *fx, const struct osi_pkg *p,
                        struct osi_hy *hy)
{
    static struct zid_doc_v2 doc;
    static uint8_t wire[ZID_DOC_V2_MAX];
    static char hex[ZID_DOC_V2_MAX * 2 + 1];
    uint8_t ed_seed[32], pq_seed[ZRS1_PQ_SEED_SIZE], pk[ZRS1_PQ_PK_SIZE];
    uint8_t other_pk[ZRS1_PQ_PK_SIZE], root[32];
    char pq_hex[ZRS1_PQ_PK_SIZE * 2 + 1], other_hex[ZRS1_PQ_PK_SIZE * 2 + 1];
    char text[512];
    struct zid_release rel;
    memset(hy, 0, sizeof(*hy));
    memset(ed_seed, 0x5A, sizeof(ed_seed));
    osi_pq_seed(0xA0, pq_seed);
    memset(&rel, 0, sizeof(rel));
    snprintf(rel.name, sizeof(rel.name), "z23");
    snprintf(rel.version, sizeof(rel.version), "1.0.a-pq");
    if (ParseHex(p->root_hex, root, 32) != 32)
        return false;
    memcpy(rel.manifest_root, root, 32);
    bool ok = zid_hybrid_pq_pubkey(pk, pq_seed) &&
              zid_hybrid_release_sign(&doc, &rel, 1,
                                      (uint64_t)platform_time_wall_unix() +
                                          86400u, ed_seed, pq_seed);
    size_t n = ok ? zid_hybrid_encode(wire, sizeof(wire), &doc) : 0;
    osi_pq_seed(0xC0, pq_seed);
    ok = n > 0 && zid_hybrid_pq_pubkey(other_pk, pq_seed);
    if (!ok)
        return false;
    HexStr(wire, n, false, hex, sizeof(hex));
    HexStr(pk, sizeof(pk), false, pq_hex, sizeof(pq_hex));
    HexStr(other_pk, sizeof(other_pk), false, other_hex, sizeof(other_hex));
    snprintf(hy->doc_v2, sizeof(hy->doc_v2), "%s/release_a_v2.zid", fx->dir);
    snprintf(hy->pins_pair, sizeof(hy->pins_pair), "%s/pins_pair", fx->dir);
    snprintf(hy->pins_wrong_pq, sizeof(hy->pins_wrong_pq), "%s/pins_wrongpq",
             fx->dir);
    snprintf(hy->pins_pair_rq, sizeof(hy->pins_pair_rq), "%s/pins_pair_rq",
             fx->dir);
    snprintf(hy->pair_line, sizeof(hy->pair_line), "zrs1 %s 0 %s",
             fx->pubkey_hex, pq_hex);
    snprintf(hy->wrong_line, sizeof(hy->wrong_line), "zrs1 %s 0 %s",
             fx->pubkey_hex, other_hex);
    snprintf(text, sizeof(text), "# pair\n%s\n", hy->pair_line);
    ok = osi_write_file(hy->doc_v2, hex, strlen(hex), 0644) &&
         osi_write_file(hy->pins_pair, text, strlen(text), 0600);
    snprintf(text, sizeof(text), "%s\n", hy->wrong_line);
    ok = ok && osi_write_file(hy->pins_wrong_pq, text, strlen(text), 0600);
    snprintf(text, sizeof(text), "%s\nrequire-pq\n", hy->pair_line);
    return ok && osi_write_file(hy->pins_pair_rq, text, strlen(text), 0600);
}

static struct osi_req osi_hy_req(const struct osi_fx *fx,
                                 const struct osi_pkg *p, const char *doc,
                                 const char *pins, const char *name)
{
    struct osi_req r = osi_good(fx, p, name);
    r.release = doc;
    r.pin_file = pins;
    return r;
}

static int test_osi_hy_install(const struct osi_fx *fx, const struct osi_pkg *p,
                               const struct osi_hy *hy)
{
    struct osi_cmd c;
    int failures = 0;
    struct osi_req r = osi_hy_req(fx, p, hy->doc_v2, hy->pins_pair, "pq-1.0");
    osi_run(fx, &r, &c);
    failures += osi_check(oc_ok(&c) && oc_bool(&c, "installed") == 1 &&
                              json_get_int(json_get(&c.reply.data,
                                                    "doc_version")) == 2 &&
                              oc_bool(&c, "pq_verified") == 1,
                          "a pair pin plus a v2 doc installs "
                          "(doc_version 2, pq_verified)");
    oc_free(&c);
    r.pin = hy->pair_line;
    r.pin_file = NULL;
    r.dry_run = true;
    osi_run(fx, &r, &c);
    failures += osi_check(oc_ok(&c) && oc_bool(&c, "dry_run") == 1,
                          "an inline pair pin works too (dry run)");
    oc_free(&c);
    return failures;
}

static int test_osi_hy_refusals(const struct osi_fx *fx,
                                const struct osi_pkg *p,
                                const struct osi_hy *hy)
{
    struct osi_cmd c;
    int failures = 0;
    int before = osi_count(fx->slots);
    struct osi_req r = osi_hy_req(fx, p, hy->doc_v2, hy->pins_wrong_pq,
                                  "pq-wrongpk");
    osi_run(fx, &r, &c);
    failures += osi_check(oc_code(&c, "PQ_KEY_MISMATCH") &&
                              osi_count(fx->slots) == before,
                          "a pinned SLH-DSA key that differs from the doc's "
                          "is PQ_KEY_MISMATCH, nothing written");
    oc_free(&c);

    r = osi_hy_req(fx, p, hy->doc_v2, fx->pins_ok, "pq-edonly");
    osi_run(fx, &r, &c);
    failures += osi_check(oc_code(&c, "RELEASE_PQ_UNPINNED") &&
                              osi_count(fx->slots) == before,
                          "a v2 doc under an Ed25519-only pin is "
                          "RELEASE_PQ_UNPINNED, nothing written");
    oc_free(&c);

    r = osi_hy_req(fx, p, hy->doc_v2, fx->pins_other, "pq-otherkey");
    osi_run(fx, &r, &c);
    failures += osi_check(oc_code(&c, "RELEASE_UNPINNED"),
                          "a v2 doc whose master key is not pinned at all "
                          "stays RELEASE_UNPINNED");
    oc_free(&c);
    return failures;
}

static int test_osi_hy_v1(const struct osi_fx *fx, const struct osi_pkg *p,
                          const struct osi_hy *hy)
{
    struct osi_cmd c;
    int failures = 0;
    struct osi_req r = osi_hy_req(fx, p, p->doc, hy->pins_pair, "v1-pair");
    osi_run(fx, &r, &c);
    failures += osi_check(oc_ok(&c) &&
                              json_get_int(json_get(&c.reply.data,
                                                    "doc_version")) == 1 &&
                              oc_bool(&c, "pq_verified") == 0,
                          "a v1 doc under a pair pin is accepted (phase 2), "
                          "pq_verified false");
    oc_free(&c);
    r.name = "v1-pair-rq";
    r.require_pq = true;
    osi_run(fx, &r, &c);
    failures += osi_check(oc_code(&c, "RELEASE_PQ_REQUIRED"),
                          "require_pq refuses a v1 doc (RELEASE_PQ_REQUIRED)");
    oc_free(&c);
    r.require_pq = false;
    r.pin_file = hy->pins_pair_rq;
    osi_run(fx, &r, &c);
    failures += osi_check(oc_code(&c, "RELEASE_PQ_REQUIRED"),
                          "a require-pq pin-file line refuses a v1 doc too");
    oc_free(&c);
    r.release = hy->doc_v2;
    r.name = "v2-rq";
    r.dry_run = true;
    osi_run(fx, &r, &c);
    failures += osi_check(oc_ok(&c) && oc_bool(&c, "pq_verified") == 1,
                          "require-pq still accepts a verified v2 doc");
    oc_free(&c);
    return failures;
}

/* Run the install against a pin file holding `body`; true iff it is refused
 * with PIN_FILE_INVALID naming `line`. */
static bool osi_bad_pin(const struct osi_fx *fx, const struct osi_pkg *p,
                        const struct osi_hy *hy, const char *body,
                        const char *line)
{
    char path[PATH_MAX];
    struct osi_cmd c;
    snprintf(path, sizeof(path), "%s/pins_bad", fx->dir);
    bool wrote = osi_write_file(path, body, strlen(body), 0600);
    struct osi_req r = osi_hy_req(fx, p, hy->doc_v2, path, "pq-badpin");
    osi_run(fx, &r, &c);
    bool ok = wrote && oc_code(&c, "PIN_FILE_INVALID") &&
              strstr(c.reply.error.evidence, line) != NULL;
    oc_free(&c);
    return ok;
}

static int test_osi_hy_pin_lines(const struct osi_fx *fx,
                                 const struct osi_pkg *p,
                                 const struct osi_hy *hy)
{
    char body[900], pk[65];
    int failures = 0;
    memcpy(pk, hy->pair_line + 5 + 64 + 3, 64);
    pk[64] = '\0';
    snprintf(body, sizeof(body), "# c\n%s\nzrs1 %s 0 %.62s\n", fx->pubkey_hex,
             fx->pubkey_hex, pk);
    failures += osi_check(osi_bad_pin(fx, p, hy, body, "line 3"),
                          "a short SLH-DSA key in a pair line names line 3");
    snprintf(body, sizeof(body), "%s\n\nzrs1 %s 1 %s\n", fx->pubkey_hex,
             fx->pubkey_hex, pk);
    failures += osi_check(osi_bad_pin(fx, p, hy, body, "line 3"),
                          "a pair line with param 1 names line 3");
    snprintf(body, sizeof(body), "zrs1 %s 0\n", fx->pubkey_hex);
    failures += osi_check(osi_bad_pin(fx, p, hy, body, "line 1"),
                          "a pair line missing its pk names line 1");
    snprintf(body, sizeof(body), "# a\n# b\n# c\nzrs1 %s 0 %s extra\n",
             fx->pubkey_hex, pk);
    failures += osi_check(osi_bad_pin(fx, p, hy, body, "line 4"),
                          "a pair line with a trailing token names line 4");
    snprintf(body, sizeof(body), "zrs1 %.63sg 0 %s\n", fx->pubkey_hex, pk);
    failures += osi_check(osi_bad_pin(fx, p, hy, body, "line 1"),
                          "a non-hex Ed25519 half in a pair line names "
                          "line 1");
    snprintf(body, sizeof(body), "%s\nzrs2 %s 0 %s\n", fx->pubkey_hex,
             fx->pubkey_hex, pk);
    failures += osi_check(osi_bad_pin(fx, p, hy, body, "line 2"),
                          "an unknown line tag names line 2");
    return failures;
}

/* l. k-of-n (docs/work/PQ_HYBRID_RELEASE_SIGNATURE.md 6.2): `threshold 2`
 * installs only with two distinct pinned pairs' docs over the same release. */
static bool osi_cosign(const struct osi_fx *fx, const struct osi_pkg *p,
                       const struct osi_hy *hy, char pins[PATH_MAX],
                       char doc_b[PATH_MAX])
{
    static struct zid_doc_v2 doc;
    static uint8_t wire[ZID_DOC_V2_MAX];
    static char hex[ZID_DOC_V2_MAX * 2 + 1];
    uint8_t ed_seed[32], pq_seed[ZRS1_PQ_SEED_SIZE], pk[ZRS1_PQ_PK_SIZE];
    uint8_t ed_pk[32];
    char ed_hex[65], pq_hex[ZRS1_PQ_PK_SIZE * 2 + 1], text[1024];
    struct zid_release rel;
    memset(ed_seed, 0x6B, sizeof(ed_seed));
    osi_pq_seed(0xC0, pq_seed);
    memset(&rel, 0, sizeof(rel));
    snprintf(rel.name, sizeof(rel.name), "z23");
    snprintf(rel.version, sizeof(rel.version), "1.0.a-pq");
    if (ParseHex(p->root_hex, rel.manifest_root, 32) != 32 ||
        !zid_hybrid_pq_pubkey(pk, pq_seed) ||
        !zid_hybrid_release_sign(&doc, &rel, 1,
                                 (uint64_t)platform_time_wall_unix() + 86400u,
                                 ed_seed, pq_seed))
        return false;
    size_t n = zid_hybrid_encode(wire, sizeof(wire), &doc);
    memcpy(ed_pk, doc.master_pubkey, 32);
    HexStr(ed_pk, 32, false, ed_hex, sizeof(ed_hex));
    HexStr(pk, sizeof(pk), false, pq_hex, sizeof(pq_hex));
    HexStr(wire, n, false, hex, sizeof(hex));
    snprintf(doc_b, PATH_MAX, "%s/release_b_v2.zid", fx->dir);
    snprintf(pins, PATH_MAX, "%s/pins_k2", fx->dir);
    snprintf(text, sizeof(text), "%s\nzrs1 %s 0 %s\nthreshold 2\n",
             hy->pair_line, ed_hex, pq_hex);
    return n > 0 && osi_write_file(doc_b, hex, strlen(hex), 0644) &&
           osi_write_file(pins, text, strlen(text), 0600);
}

static int test_osi_threshold(const struct osi_fx *fx, const struct osi_pkg *p,
                              const struct osi_hy *hy)
{
    struct osi_cmd c;
    int failures = 0;
    char pins[PATH_MAX], doc_b[PATH_MAX];
    if (!osi_cosign(fx, p, hy, pins, doc_b))
        return osi_check(false, "threshold fixture");
    int before = osi_count(fx->slots);
    struct osi_req r = osi_hy_req(fx, p, hy->doc_v2, pins, "k2-one");
    osi_run(fx, &r, &c);
    failures += osi_check(oc_code(&c, "THRESHOLD_SINGLE_DOC") &&
                              osi_count(fx->slots) == before,
                          "threshold 2 with one doc is refused, nothing "
                          "written");
    oc_free(&c);
    r.name = "k2-two";
    r.cosigs = doc_b;
    osi_run(fx, &r, &c);
    failures += osi_check(oc_ok(&c) && oc_bool(&c, "installed") == 1 &&
                              json_get_int(json_get(&c.reply.data,
                                                    "signers_matched")) == 2 &&
                              json_get_int(json_get(&c.reply.data,
                                                    "threshold")) == 2,
                          "threshold 2 with two distinct pinned pairs "
                          "installs (threshold 2, signers_matched 2)");
    oc_free(&c);
    r.name = "k2-dup";
    r.cosigs = hy->doc_v2;
    osi_run(fx, &r, &c);
    failures += osi_check(oc_code(&c, "THRESHOLD_DUPLICATE_SIGNER"),
                          "the same pair twice does not reach threshold 2");
    oc_free(&c);
    return failures;
}

static int test_osi_hybrid(const struct osi_fx *fx, const struct osi_pkg *p)
{
    struct osi_hy hy;
    int failures = 0;
    if (!osi_hy_init(fx, p, &hy))
        return osi_check(false, "hybrid fixture");
    failures += test_osi_hy_install(fx, p, &hy);
    failures += test_osi_hy_refusals(fx, p, &hy);
    failures += test_osi_hy_v1(fx, p, &hy);
    failures += test_osi_hy_pin_lines(fx, p, &hy);
    failures += test_osi_threshold(fx, p, &hy);
    return failures;
}

int test_ops_slot_install(void)
{
    struct osi_fx fx;
    struct osi_pkg a, b;
    int failures = 0;
    printf("\n=== ops slot install tests ===\n");
    bool ready = osi_fx_init(&fx) && osi_write_pins(&fx) &&
                 osi_make_pkg(&fx, &a, "a", 0x11) &&
                 osi_make_pkg(&fx, &b, "b", 0x22);
    if (!ready) {
        printf("ops_slot_install: fixture... FAIL\n");
        return 1;
    }
    failures += test_osi_install(&fx, &a);
    failures += test_osi_unpinned(&fx, &a);
    failures += test_osi_tamper_root(&fx, &a, &b);
    failures += test_osi_idempotent(&fx, &a, &b);
    failures += test_osi_names_dry(&fx, &a);
    failures += test_osi_verify(&fx, &a, &b);
    failures += test_osi_doc_and_path(&fx, &a);
    failures += test_osi_hybrid(&fx, &a);
    failures += release_threshold_suite();
    osi_pkg_free(&a);
    osi_pkg_free(&b);
    unsetenv("ZCL_BINARY_SLOTS_DIR");
    osi_rm_tree(fx.dir);
    printf("=== OPS_SLOT_INSTALL: %d failure(s) ===\n", failures);
    return failures;
}
