/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_recipe — implementation of the declarative C23 build recipe
 * codec declared in vcs/package_recipe.h. Pure bytes: no filesystem, no
 * compiler, no execution. The node NEVER compiles or executes downloaded
 * code; compilation belongs to the external verifier (slice 6). */

#include "vcs/package_recipe.h"

#include "codec/cursor.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RECIPE_LOG "vcs.recipe"

static const uint8_t recipe_wire_magic[VCS_PACKAGE_RECIPE_WIRE_MAGIC_BYTES] =
    { 'Z', 'C', 'L', 'R', 'C', 'P', '\r', '\n' };
static const uint8_t recipe_root_domain[] = VCS_PACKAGE_RECIPE_ROOT_DOMAIN;

/* ── error strings ──────────────────────────────────────────────────── */

const char *vcs_package_recipe_error_string(
    enum vcs_package_recipe_error error)
{
    switch (error) {
    case VCS_PACKAGE_RECIPE_OK: return "ok";
    case VCS_PACKAGE_RECIPE_ERR_NULL: return "null-argument";
    case VCS_PACKAGE_RECIPE_ERR_ALLOC: return "allocation-failure";
    case VCS_PACKAGE_RECIPE_ERR_SCHEMA_VERSION: return "schema-version";
    case VCS_PACKAGE_RECIPE_ERR_WIRE_MAGIC: return "wire-magic";
    case VCS_PACKAGE_RECIPE_ERR_WIRE_OVERSIZE: return "wire-oversize";
    case VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED: return "wire-truncated";
    case VCS_PACKAGE_RECIPE_ERR_WIRE_TRAILING: return "wire-trailing";
    case VCS_PACKAGE_RECIPE_ERR_LIST_ORDER: return "list-not-canonical-order";
    case VCS_PACKAGE_RECIPE_ERR_COUNT_BOUND: return "list-count-bound";
    case VCS_PACKAGE_RECIPE_ERR_PATH: return "path-grammar";
    case VCS_PACKAGE_RECIPE_ERR_DEFINE: return "define-grammar";
    case VCS_PACKAGE_RECIPE_ERR_LIBRARY: return "library-not-allowed";
    case VCS_PACKAGE_RECIPE_ERR_SOURCES_EMPTY: return "sources-empty";
    case VCS_PACKAGE_RECIPE_ERR_TEST_SECONDS: return "test-seconds-bound";
    case VCS_PACKAGE_RECIPE_ERR_MEMORY_BYTES: return "memory-bytes-bound";
    }
    return "unknown-error";
}

/* ── library allowlist ──────────────────────────────────────────────── */

uint8_t vcs_package_recipe_library_id(const char *name)
{
    if (!name)
        return 0;
    if (strcmp(name, "libc") == 0)
        return VCS_PACKAGE_RECIPE_LIB_LIBC;
    if (strcmp(name, "libm") == 0)
        return VCS_PACKAGE_RECIPE_LIB_LIBM;
    if (strcmp(name, "pthread") == 0)
        return VCS_PACKAGE_RECIPE_LIB_PTHREAD;
    return 0;
}

const char *vcs_package_recipe_library_name(uint8_t id)
{
    switch (id) {
    case VCS_PACKAGE_RECIPE_LIB_LIBC: return "libc";
    case VCS_PACKAGE_RECIPE_LIB_LIBM: return "libm";
    case VCS_PACKAGE_RECIPE_LIB_PTHREAD: return "pthread";
    }
    return NULL;
}

/* ── lifecycle ──────────────────────────────────────────────────────── */

void vcs_package_recipe_init(struct vcs_package_recipe *recipe)
{
    memset(recipe, 0, sizeof(*recipe));
    recipe->schema_version = VCS_PACKAGE_RECIPE_VERSION;
}

static void recipe_strings_free(struct vcs_package_recipe_strings *list)
{
    for (size_t i = 0; i < list->count; i++)
        free(list->items[i]);
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

void vcs_package_recipe_free(struct vcs_package_recipe *recipe)
{
    if (!recipe)
        return;
    recipe_strings_free(&recipe->public_headers);
    recipe_strings_free(&recipe->sources);
    recipe_strings_free(&recipe->test_sources);
    recipe_strings_free(&recipe->include_dirs);
    recipe_strings_free(&recipe->defines);
    recipe->library_count = 0;
}

/* ── field grammars ─────────────────────────────────────────────────── */

static bool recipe_suffix(const char *path, const char *suffix)
{
    size_t plen = strlen(path);
    size_t slen = strlen(suffix);
    return plen > slen && strcmp(path + plen - slen, suffix) == 0;
}

static bool recipe_define_valid(const char *define)
{
    if (!define || !define[0] || strlen(define) > VCS_PACKAGE_RECIPE_DEFINE_MAX)
        return false;
    const char *p = define;
    if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || *p == '_'))
        return false;
    size_t name_len = 0;
    for (; *p && *p != '='; p++) {
        char c = *p;
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_'))
            return false;
        if (++name_len > 32)
            return false;
    }
    if (*p == '=') {
        size_t value_len = 0;
        for (p++; *p; p++) {
            char c = *p;
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '+' ||
                      c == '.' || c == ',' || c == ':' || c == '-';
            if (!ok)
                return false;
            if (++value_len > 31)
                return false;
        }
    }
    return true;
}

/* ── string-list insertion (canonical order, duplicates rejected) ───── */

static bool recipe_strings_insert(struct vcs_package_recipe_strings *list,
                                  const char *entry, size_t bound,
                                  enum vcs_package_recipe_error *err_out)
{
    if (list->count >= bound) {
        if (err_out)
            *err_out = VCS_PACKAGE_RECIPE_ERR_COUNT_BOUND;
        return false;
    }
    size_t lo = 0;
    size_t hi = list->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (strcmp(list->items[mid], entry) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo < list->count && strcmp(list->items[lo], entry) == 0) {
        if (err_out)
            *err_out = VCS_PACKAGE_RECIPE_ERR_LIST_ORDER;
        return false;
    }
    if (list->count == list->cap) {
        size_t ncap = list->cap ? list->cap * 2 : 8;
        char **nitems = zcl_realloc(list->items, ncap * sizeof(*nitems),
                                    "vcs_recipe_list");
        if (!nitems) {
            if (err_out)
                *err_out = VCS_PACKAGE_RECIPE_ERR_ALLOC;
            LOG_ERROR(RECIPE_LOG, "list grow to %zu entries", ncap);
            return false;
        }
        list->items = nitems;
        list->cap = ncap;
    }
    char *copy = zcl_malloc(strlen(entry) + 1, "vcs_recipe_entry");
    if (!copy) {
        if (err_out)
            *err_out = VCS_PACKAGE_RECIPE_ERR_ALLOC;
        return false;
    }
    strcpy(copy, entry);
    memmove(list->items + lo + 1, list->items + lo,
            (list->count - lo) * sizeof(*list->items));
    list->items[lo] = copy;
    list->count++;
    return true;
}

static bool recipe_add_path(struct vcs_package_recipe_strings *list,
                            const char *path, const char *suffix,
                            size_t bound,
                            enum vcs_package_recipe_error *err_out)
{
    enum vcs_package_recipe_error err;
    if (!err_out)
        err_out = &err;
    if (!path || !vcs_package_path_valid(path) ||
        (suffix && !recipe_suffix(path, suffix))) {
        *err_out = VCS_PACKAGE_RECIPE_ERR_PATH;
        return false;
    }
    return recipe_strings_insert(list, path, bound, err_out);
}

bool vcs_package_recipe_add_header(struct vcs_package_recipe *r,
                                   const char *path,
                                   enum vcs_package_recipe_error *err_out)
{
    if (!r) {
        if (err_out)
            *err_out = VCS_PACKAGE_RECIPE_ERR_NULL;
        return false;
    }
    return recipe_add_path(&r->public_headers, path, ".h",
                           VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST, err_out);
}

bool vcs_package_recipe_add_source(struct vcs_package_recipe *r,
                                   const char *path,
                                   enum vcs_package_recipe_error *err_out)
{
    if (!r) {
        if (err_out)
            *err_out = VCS_PACKAGE_RECIPE_ERR_NULL;
        return false;
    }
    return recipe_add_path(&r->sources, path, ".c",
                           VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST, err_out);
}

bool vcs_package_recipe_add_test_source(
    struct vcs_package_recipe *r, const char *path,
    enum vcs_package_recipe_error *err_out)
{
    if (!r) {
        if (err_out)
            *err_out = VCS_PACKAGE_RECIPE_ERR_NULL;
        return false;
    }
    return recipe_add_path(&r->test_sources, path, ".c",
                           VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST, err_out);
}

bool vcs_package_recipe_add_include_dir(
    struct vcs_package_recipe *r, const char *dir,
    enum vcs_package_recipe_error *err_out)
{
    if (!r) {
        if (err_out)
            *err_out = VCS_PACKAGE_RECIPE_ERR_NULL;
        return false;
    }
    return recipe_add_path(&r->include_dirs, dir, NULL,
                           VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST, err_out);
}

bool vcs_package_recipe_add_define(struct vcs_package_recipe *r,
                                   const char *define,
                                   enum vcs_package_recipe_error *err_out)
{
    enum vcs_package_recipe_error err;
    if (!err_out)
        err_out = &err;
    if (!r) {
        *err_out = VCS_PACKAGE_RECIPE_ERR_NULL;
        return false;
    }
    if (!recipe_define_valid(define)) {
        *err_out = VCS_PACKAGE_RECIPE_ERR_DEFINE;
        return false;
    }
    return recipe_strings_insert(&r->defines, define,
                                 VCS_PACKAGE_RECIPE_MAX_DEFINES, err_out);
}

bool vcs_package_recipe_add_library(struct vcs_package_recipe *r,
                                    uint8_t library_id,
                                    enum vcs_package_recipe_error *err_out)
{
    enum vcs_package_recipe_error err;
    if (!err_out)
        err_out = &err;
    if (!r) {
        *err_out = VCS_PACKAGE_RECIPE_ERR_NULL;
        return false;
    }
    if (!vcs_package_recipe_library_name(library_id)) {
        *err_out = VCS_PACKAGE_RECIPE_ERR_LIBRARY;
        return false;
    }
    if (r->library_count >= VCS_PACKAGE_RECIPE_MAX_LIBRARIES) {
        *err_out = VCS_PACKAGE_RECIPE_ERR_COUNT_BOUND;
        return false;
    }
    size_t lo = 0;
    size_t hi = r->library_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (r->libraries[mid] < library_id)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo < r->library_count && r->libraries[lo] == library_id) {
        *err_out = VCS_PACKAGE_RECIPE_ERR_LIST_ORDER;
        return false;
    }
    memmove(r->libraries + lo + 1, r->libraries + lo,
            r->library_count - lo);
    r->libraries[lo] = library_id;
    r->library_count++;
    return true;
}

void vcs_package_recipe_set_test_limits(struct vcs_package_recipe *r,
                                        uint8_t expected_exit_code,
                                        uint32_t maximum_seconds,
                                        uint64_t maximum_memory_bytes)
{
    if (!r)
        return;
    r->expected_test_exit_code = expected_exit_code;
    r->maximum_test_seconds = maximum_seconds;
    r->maximum_memory_bytes = maximum_memory_bytes;
}

/* ── validation ─────────────────────────────────────────────────────── */

enum vcs_package_recipe_error vcs_package_recipe_validate(
    const struct vcs_package_recipe *recipe)
{
    if (!recipe)
        return VCS_PACKAGE_RECIPE_ERR_NULL;
    if (recipe->schema_version != VCS_PACKAGE_RECIPE_VERSION)
        return VCS_PACKAGE_RECIPE_ERR_SCHEMA_VERSION;
    if (recipe->sources.count == 0)
        return VCS_PACKAGE_RECIPE_ERR_SOURCES_EMPTY;
    if (recipe->maximum_test_seconds == 0 ||
        recipe->maximum_test_seconds > VCS_PACKAGE_RECIPE_MAX_TEST_SECONDS)
        return VCS_PACKAGE_RECIPE_ERR_TEST_SECONDS;
    if (recipe->maximum_memory_bytes < VCS_PACKAGE_RECIPE_MIN_MEMORY_BYTES ||
        recipe->maximum_memory_bytes > VCS_PACKAGE_RECIPE_MAX_MEMORY_BYTES)
        return VCS_PACKAGE_RECIPE_ERR_MEMORY_BYTES;
    if (recipe->library_count > VCS_PACKAGE_RECIPE_MAX_LIBRARIES)
        return VCS_PACKAGE_RECIPE_ERR_COUNT_BOUND;
    for (size_t i = 0; i < recipe->library_count; i++) {
        if (!vcs_package_recipe_library_name(recipe->libraries[i]))
            return VCS_PACKAGE_RECIPE_ERR_LIBRARY;
        if (i > 0 && recipe->libraries[i] <= recipe->libraries[i - 1])
            return VCS_PACKAGE_RECIPE_ERR_LIST_ORDER;
    }
    /* The struct is public, so validate re-checks every list: grammar,
     * count bound, and strictly ascending canonical order — a caller that
     * bypassed the add_* builders is held to the same rules. */
    const struct {
        const struct vcs_package_recipe_strings *list;
        const char *suffix;
        size_t bound;
        bool is_define;
    } lists[] = {
        { &recipe->public_headers, ".h",
          VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST, false },
        { &recipe->sources, ".c",
          VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST, false },
        { &recipe->test_sources, ".c",
          VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST, false },
        { &recipe->include_dirs, NULL,
          VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST, false },
        { &recipe->defines, NULL, VCS_PACKAGE_RECIPE_MAX_DEFINES, true },
    };
    for (size_t l = 0; l < sizeof(lists) / sizeof(lists[0]); l++) {
        const struct vcs_package_recipe_strings *list = lists[l].list;
        if (list->count > lists[l].bound)
            return VCS_PACKAGE_RECIPE_ERR_COUNT_BOUND;
        for (size_t i = 0; i < list->count; i++) {
            const char *entry = list->items[i];
            if (!entry)
                return VCS_PACKAGE_RECIPE_ERR_NULL;
            bool grammar = lists[l].is_define
                ? recipe_define_valid(entry)
                : (vcs_package_path_valid(entry) &&
                   (!lists[l].suffix ||
                    recipe_suffix(entry, lists[l].suffix)));
            if (!grammar)
                return lists[l].is_define ? VCS_PACKAGE_RECIPE_ERR_DEFINE
                                          : VCS_PACKAGE_RECIPE_ERR_PATH;
            if (i > 0 && strcmp(list->items[i - 1], entry) >= 0)
                return VCS_PACKAGE_RECIPE_ERR_LIST_ORDER;
        }
    }
    return VCS_PACKAGE_RECIPE_OK;
}

/* ── serialization ──────────────────────────────────────────────────── */

static size_t recipe_strings_wire_bytes(
    const struct vcs_package_recipe_strings *list)
{
    size_t n = 2;
    for (size_t i = 0; i < list->count; i++)
        n += 2 + strlen(list->items[i]);
    return n;
}

static size_t recipe_wire_bytes(const struct vcs_package_recipe *r)
{
    return VCS_PACKAGE_RECIPE_WIRE_MAGIC_BYTES + 2u +
           recipe_strings_wire_bytes(&r->public_headers) +
           recipe_strings_wire_bytes(&r->sources) +
           recipe_strings_wire_bytes(&r->test_sources) +
           recipe_strings_wire_bytes(&r->include_dirs) +
           recipe_strings_wire_bytes(&r->defines) +
           2u + r->library_count + 1u + 4u + 8u;
}

static bool recipe_strings_write(
    struct zcl_codec_writer *writer,
    const struct vcs_package_recipe_strings *list)
{
    if (!zcl_codec_write_u16le(writer, (uint16_t)list->count)) return false;
    for (size_t i = 0; i < list->count; i++)
        if (!zcl_codec_write_u16_string(writer, list->items[i],
                                        strlen(list->items[i])))
            return false;
    return true;
}

enum vcs_package_recipe_error vcs_package_recipe_serialize(
    const struct vcs_package_recipe *recipe, uint8_t **out, size_t *out_len)
{
    if (!out || !out_len)
        return VCS_PACKAGE_RECIPE_ERR_NULL;
    *out = NULL;
    *out_len = 0;
    enum vcs_package_recipe_error err =
        vcs_package_recipe_validate(recipe);
    if (err != VCS_PACKAGE_RECIPE_OK)
        return err;
    size_t len = recipe_wire_bytes(recipe);
    if (len > VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES)
        return VCS_PACKAGE_RECIPE_ERR_WIRE_OVERSIZE;
    uint8_t *wire = zcl_malloc(len, "vcs_recipe_wire");
    if (!wire)
        LOG_RETURN(VCS_PACKAGE_RECIPE_ERR_ALLOC, RECIPE_LOG,
                   "alloc %zu recipe wire bytes", len);
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, wire, len);
    bool ok = zcl_codec_write_bytes(
                  &writer, recipe_wire_magic,
                  VCS_PACKAGE_RECIPE_WIRE_MAGIC_BYTES) &&
        zcl_codec_write_u16le(&writer, recipe->schema_version) &&
        recipe_strings_write(&writer, &recipe->public_headers) &&
        recipe_strings_write(&writer, &recipe->sources) &&
        recipe_strings_write(&writer, &recipe->test_sources) &&
        recipe_strings_write(&writer, &recipe->include_dirs) &&
        recipe_strings_write(&writer, &recipe->defines) &&
        zcl_codec_write_u16le(&writer, (uint16_t)recipe->library_count) &&
        zcl_codec_write_bytes(&writer, recipe->libraries,
                              recipe->library_count) &&
        zcl_codec_write_u8(&writer, recipe->expected_test_exit_code) &&
        zcl_codec_write_u32le(&writer, recipe->maximum_test_seconds) &&
        zcl_codec_write_u64le(&writer, recipe->maximum_memory_bytes);
    size_t written = 0;
    ok = ok && zcl_codec_writer_finish(&writer, &written) && written == len;
    if (!ok) {
        free(wire);
        return VCS_PACKAGE_RECIPE_ERR_WIRE_OVERSIZE;
    }
    *out = wire;
    *out_len = written;
    return VCS_PACKAGE_RECIPE_OK;
}

/* ── parse ──────────────────────────────────────────────────────────── */

/* Read one string list (count-prefixed) through the canonical insertion
 * path; unsorted input lands out of insertion order, so the wire's own
 * order is checked against the previous entry first. grammar_err selects
 * the path/define rejection; suffix may be NULL. */
static enum vcs_package_recipe_error recipe_parse_strings(
    struct zcl_codec_reader *reader,
    struct vcs_package_recipe_strings *list,
    size_t bound, const char *suffix, bool is_define)
{
    uint16_t count = 0;
    if (!zcl_codec_read_u16le(reader, &count))
        return VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED;
    char prev[VCS_PACKAGE_PATH_MAX + 1];
    prev[0] = '\0';
    for (uint16_t i = 0; i < count; i++) {
        uint16_t len = 0;
        if (!zcl_codec_read_u16le(reader, &len))
            return VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED;
        if (len == 0 || zcl_codec_reader_remaining(reader) < len)
            return VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED;
        char *entry = zcl_malloc((size_t)len + 1, "vcs_recipe_parse_entry");
        if (!entry)
            LOG_RETURN(VCS_PACKAGE_RECIPE_ERR_ALLOC, RECIPE_LOG,
                       "alloc %u entry bytes", (unsigned)len + 1);
        if (!zcl_codec_read_bytes(reader, entry, len)) {
            free(entry);
            return VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED;
        }
        entry[len] = '\0';
        bool grammar = memchr(entry, '\0', len) == NULL &&
            (is_define ? recipe_define_valid(entry)
            : (vcs_package_path_valid(entry) &&
               (!suffix || recipe_suffix(entry, suffix))));
        if (!grammar) {
            free(entry);
            return is_define ? VCS_PACKAGE_RECIPE_ERR_DEFINE
                             : VCS_PACKAGE_RECIPE_ERR_PATH;
        }
        if (prev[0] && strcmp(prev, entry) >= 0) {
            free(entry);
            return VCS_PACKAGE_RECIPE_ERR_LIST_ORDER;
        }
        enum vcs_package_recipe_error err = VCS_PACKAGE_RECIPE_OK;
        bool ok = recipe_strings_insert(list, entry, bound, &err);
        if (ok)
            snprintf(prev, sizeof(prev), "%s", entry);
        free(entry);
        if (!ok)
            return err;
    }
    return VCS_PACKAGE_RECIPE_OK;
}

enum vcs_package_recipe_error vcs_package_recipe_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_package_recipe *out)
{
    if (!wire || !out)
        return VCS_PACKAGE_RECIPE_ERR_NULL;
    vcs_package_recipe_init(out);
    if (wire_len > VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES)
        return VCS_PACKAGE_RECIPE_ERR_WIRE_OVERSIZE;
    /* Smallest legal wire: magic + version + five empty string lists +
     * the library count + the 13 scalar bytes. */
    if (wire_len < VCS_PACKAGE_RECIPE_WIRE_MAGIC_BYTES + 2u + 10u + 2u + 13u)
        return VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED;
    struct zcl_codec_reader reader;
    zcl_codec_reader_init(&reader, wire, wire_len);
    uint8_t magic[VCS_PACKAGE_RECIPE_WIRE_MAGIC_BYTES];
    if (!zcl_codec_read_bytes(&reader, magic, sizeof(magic)) ||
        memcmp(magic, recipe_wire_magic, sizeof(magic)) != 0)
        return VCS_PACKAGE_RECIPE_ERR_WIRE_MAGIC;
    uint16_t version = 0;
    if (!zcl_codec_read_u16le(&reader, &version))
        return VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED;
    if (version != VCS_PACKAGE_RECIPE_VERSION)
        return VCS_PACKAGE_RECIPE_ERR_SCHEMA_VERSION;
    out->schema_version = version;

    enum vcs_package_recipe_error err;
    err = recipe_parse_strings(&reader, &out->public_headers,
                               VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST, ".h",
                               false);
    if (err == VCS_PACKAGE_RECIPE_OK)
        err = recipe_parse_strings(&reader, &out->sources,
                                   VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST,
                                   ".c", false);
    if (err == VCS_PACKAGE_RECIPE_OK)
        err = recipe_parse_strings(&reader, &out->test_sources,
                                   VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST,
                                   ".c", false);
    if (err == VCS_PACKAGE_RECIPE_OK)
        err = recipe_parse_strings(&reader, &out->include_dirs,
                                   VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST,
                                   NULL, false);
    if (err == VCS_PACKAGE_RECIPE_OK)
        err = recipe_parse_strings(&reader, &out->defines,
                                   VCS_PACKAGE_RECIPE_MAX_DEFINES, NULL,
                                   true);
    if (err != VCS_PACKAGE_RECIPE_OK)
        goto reject;

    uint16_t lib_count = 0;
    if (!zcl_codec_read_u16le(&reader, &lib_count)) {
        err = VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED;
        goto reject;
    }
    if (lib_count > VCS_PACKAGE_RECIPE_MAX_LIBRARIES) {
        err = VCS_PACKAGE_RECIPE_ERR_COUNT_BOUND;
        goto reject;
    }
    for (uint16_t i = 0; i < lib_count; i++) {
        uint8_t id = 0;
        if (!zcl_codec_read_u8(&reader, &id)) {
            err = VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED;
            goto reject;
        }
        if (!vcs_package_recipe_library_name(id)) {
            err = VCS_PACKAGE_RECIPE_ERR_LIBRARY;
            goto reject;
        }
        if (i > 0 && id <= out->libraries[i - 1]) {
            err = VCS_PACKAGE_RECIPE_ERR_LIST_ORDER;
            goto reject;
        }
        out->libraries[i] = id;
    }
    out->library_count = lib_count;

    if (!zcl_codec_read_u8(&reader, &out->expected_test_exit_code)) {
        err = VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED;
        goto reject;
    }
    uint32_t seconds = 0;
    uint64_t memory = 0;
    if (!zcl_codec_read_u32le(&reader, &seconds) ||
        !zcl_codec_read_u64le(&reader, &memory)) {
        err = VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED;
        goto reject;
    }
    out->maximum_test_seconds = seconds;
    out->maximum_memory_bytes = memory;

    if (!zcl_codec_reader_finish(&reader)) {
        err = VCS_PACKAGE_RECIPE_ERR_WIRE_TRAILING;
        goto reject;
    }
    err = vcs_package_recipe_validate(out);
    if (err != VCS_PACKAGE_RECIPE_OK)
        goto reject;
    return VCS_PACKAGE_RECIPE_OK;

reject:
    vcs_package_recipe_free(out);
    vcs_package_recipe_init(out);
    return err;
}

/* ── recipe root ────────────────────────────────────────────────────── */

enum vcs_package_recipe_error vcs_package_recipe_root(
    const struct vcs_package_recipe *recipe, uint8_t out[32])
{
    if (!out)
        return VCS_PACKAGE_RECIPE_ERR_NULL;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum vcs_package_recipe_error err =
        vcs_package_recipe_serialize(recipe, &wire, &wire_len);
    if (err != VCS_PACKAGE_RECIPE_OK)
        return err;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, recipe_root_domain, sizeof(recipe_root_domain));
    sha3_256_write(&ctx, wire, wire_len);
    sha3_256_finalize(&ctx, out);
    free(wire);
    return VCS_PACKAGE_RECIPE_OK;
}

/* ── manifest membership cross-check ────────────────────────────────── */

static bool recipe_manifest_has_file(const struct vcs_package_manifest *m,
                                     const char *path)
{
    for (size_t i = 0; i < m->count; i++)
        if (strcmp(m->files[i].path, path) == 0)
            return true;
    return false;
}

static bool recipe_manifest_has_dir(const struct vcs_package_manifest *m,
                                    const char *dir)
{
    size_t dlen = strlen(dir);
    for (size_t i = 0; i < m->count; i++) {
        const char *path = m->files[i].path;
        if (strncmp(path, dir, dlen) == 0 && path[dlen] == '/' &&
            path[dlen + 1] != '\0')
            return true;
    }
    return false;
}

static bool recipe_list_in_manifest(
    const struct vcs_package_recipe_strings *list, const char *list_name,
    const struct vcs_package_manifest *m, char *detail_out,
    size_t detail_cap)
{
    for (size_t i = 0; i < list->count; i++) {
        if (!recipe_manifest_has_file(m, list->items[i])) {
            if (detail_out && detail_cap > 0)
                snprintf(detail_out, detail_cap, "%s: %s", list_name,
                         list->items[i]);
            return false;
        }
    }
    return true;
}

bool vcs_package_recipe_files_in_manifest(
    const struct vcs_package_recipe *recipe,
    const struct vcs_package_manifest *manifest, char *detail_out,
    size_t detail_cap)
{
    if (!recipe || !manifest)
        LOG_RETURN(false, RECIPE_LOG, "null recipe/manifest");
    if (!recipe_list_in_manifest(&recipe->public_headers, "public_headers",
                                 manifest, detail_out, detail_cap) ||
        !recipe_list_in_manifest(&recipe->sources, "sources", manifest,
                                 detail_out, detail_cap) ||
        !recipe_list_in_manifest(&recipe->test_sources, "test_sources",
                                 manifest, detail_out, detail_cap))
        return false;
    for (size_t i = 0; i < recipe->include_dirs.count; i++) {
        if (!recipe_manifest_has_dir(manifest,
                                     recipe->include_dirs.items[i])) {
            if (detail_out && detail_cap > 0)
                snprintf(detail_out, detail_cap, "include_dirs: %s",
                         recipe->include_dirs.items[i]);
            return false;
        }
    }
    return true;
}
