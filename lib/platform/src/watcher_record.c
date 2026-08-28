/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "platform/watcher_record.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define RECORD_MAGIC "z23-watcher-owner-v1\n"

static bool fixed_hex(const char *s, size_t size)
{
    if (!s) return false;
    for (size_t i = 0; i < size; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return s[size] == 0;
}

static bool path_valid(const char *path)
{
    size_t n = 0;
    if (path) while (n < PLATFORM_WATCHER_RECORD_PATH_MAX && path[n]) ++n;
    if (n == 0 || n == PLATFORM_WATCHER_RECORD_PATH_MAX) return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)path[i];
        if (c < 0x20u || c == 0x7fu) return false;
    }
    return true;
}

static bool identity_valid(const struct platform_watcher_file_identity *id)
{
    return id && (id->volume != 0 || id->file_low != 0 || id->file_high != 0);
}

bool platform_watcher_record_is_valid(const struct platform_watcher_record *r)
{
    return r && r->version == PLATFORM_WATCHER_RECORD_VERSION &&
           fixed_hex(r->nonce, PLATFORM_WATCHER_RECORD_NONCE_HEX) &&
           r->pid != 0 && r->start_token != 0 &&
           (r->mode == PLATFORM_WATCHER_MODE_VERIFY ||
            r->mode == PLATFORM_WATCHER_MODE_AUTO) &&
           path_valid(r->canonical_root) && identity_valid(&r->root_identity) &&
           path_valid(r->canonical_image) && identity_valid(&r->image_identity) &&
           r->image_size != 0 &&
           fixed_hex(r->image_sha256, PLATFORM_WATCHER_RECORD_HASH_HEX) &&
           (r->state == PLATFORM_WATCHER_STATE_STARTING ||
            r->state == PLATFORM_WATCHER_STATE_READY ||
            r->state == PLATFORM_WATCHER_STATE_STOPPING);
}

static const char *mode_name(enum platform_watcher_mode mode)
{ return mode == PLATFORM_WATCHER_MODE_VERIFY ? "verify" : "auto"; }
static const char *state_name(enum platform_watcher_state state)
{
    if (state == PLATFORM_WATCHER_STATE_STARTING) return "starting";
    if (state == PLATFORM_WATCHER_STATE_READY) return "ready";
    return "stopping";
}

bool platform_watcher_record_serialize(const struct platform_watcher_record *r,
                                       char *out, size_t cap, size_t *written)
{
    if (written) *written = 0;
    if (!out || cap == 0 || !platform_watcher_record_is_valid(r)) return false;
    int n = snprintf(out, cap,
        RECORD_MAGIC
        "nonce=%s\npid=%" PRIu64 "\nstart_token=%" PRIu64 "\nmode=%s\n"
        "root_path=%s\nroot_volume=%" PRIu64 "\nroot_file_low=%" PRIu64
        "\nroot_file_high=%" PRIu64 "\nimage_path=%s\nimage_volume=%" PRIu64
        "\nimage_file_low=%" PRIu64 "\nimage_file_high=%" PRIu64
        "\nimage_size=%" PRIu64 "\nimage_sha256=%s\nstate=%s\n",
        r->nonce, r->pid, r->start_token, mode_name(r->mode),
        r->canonical_root, r->root_identity.volume, r->root_identity.file_low,
        r->root_identity.file_high, r->canonical_image,
        r->image_identity.volume, r->image_identity.file_low,
        r->image_identity.file_high, r->image_size, r->image_sha256,
        state_name(r->state));
    if (n < 0 || (size_t)n >= cap || (size_t)n >= PLATFORM_WATCHER_RECORD_ENCODED_MAX) {
        out[0] = 0; return false;
    }
    if (written) *written = (size_t)n;
    return true;
}

static bool take_line(const char **cursor, const char *end, const char *prefix,
                      char *out, size_t cap)
{
    size_t pn = strlen(prefix); const char *p = *cursor;
    if ((size_t)(end - p) < pn || memcmp(p, prefix, pn) != 0) return false;
    p += pn; const char *nl = memchr(p, '\n', (size_t)(end - p));
    size_t n = nl ? (size_t)(nl - p) : 0;
    if (!nl || n == 0 || n >= cap || memchr(p, '\0', n)) return false;
    memcpy(out, p, n); out[n] = 0; *cursor = nl + 1; return true;
}

static bool decimal(const char *s, uint64_t *out)
{
    if (!s || !*s || (s[0] == '0' && s[1])) return false;
    uint64_t value = 0;
    for (size_t i = 0; s[i]; ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        unsigned digit = (unsigned)(s[i] - '0');
        if (value > (UINT64_MAX - digit) / 10u) return false;
        value = value * 10u + digit;
    }
    *out = value; return true;
}

static bool number_line(const char **p, const char *end, const char *prefix,
                        uint64_t *out)
{
    char value[32];
    return take_line(p, end, prefix, value, sizeof(value)) && decimal(value, out);
}

bool platform_watcher_record_parse(const char *encoded, size_t size,
                                   struct platform_watcher_record *out)
{
    if (!encoded || !out || size == 0 ||
        size >= PLATFORM_WATCHER_RECORD_ENCODED_MAX ||
        size < sizeof(RECORD_MAGIC) - 1u || memchr(encoded, '\0', size)) return false;
    struct platform_watcher_record r = {0};
    const char *p = encoded, *end = encoded + size;
    size_t magic = sizeof(RECORD_MAGIC) - 1u;
    if (memcmp(p, RECORD_MAGIC, magic) != 0) return false;
    p += magic; r.version = PLATFORM_WATCHER_RECORD_VERSION;
    char mode[16], state[16];
    if (!take_line(&p,end,"nonce=",r.nonce,sizeof(r.nonce)) ||
        !number_line(&p,end,"pid=",&r.pid) ||
        !number_line(&p,end,"start_token=",&r.start_token) ||
        !take_line(&p,end,"mode=",mode,sizeof(mode)) ||
        !take_line(&p,end,"root_path=",r.canonical_root,sizeof(r.canonical_root)) ||
        !number_line(&p,end,"root_volume=",&r.root_identity.volume) ||
        !number_line(&p,end,"root_file_low=",&r.root_identity.file_low) ||
        !number_line(&p,end,"root_file_high=",&r.root_identity.file_high) ||
        !take_line(&p,end,"image_path=",r.canonical_image,sizeof(r.canonical_image)) ||
        !number_line(&p,end,"image_volume=",&r.image_identity.volume) ||
        !number_line(&p,end,"image_file_low=",&r.image_identity.file_low) ||
        !number_line(&p,end,"image_file_high=",&r.image_identity.file_high) ||
        !number_line(&p,end,"image_size=",&r.image_size) ||
        !take_line(&p,end,"image_sha256=",r.image_sha256,sizeof(r.image_sha256)) ||
        !take_line(&p,end,"state=",state,sizeof(state)) || p != end) return false;
    if (strcmp(mode,"verify") == 0) r.mode = PLATFORM_WATCHER_MODE_VERIFY;
    else if (strcmp(mode,"auto") == 0) r.mode = PLATFORM_WATCHER_MODE_AUTO;
    else return false;
    if (strcmp(state,"starting") == 0) r.state = PLATFORM_WATCHER_STATE_STARTING;
    else if (strcmp(state,"ready") == 0) r.state = PLATFORM_WATCHER_STATE_READY;
    else if (strcmp(state,"stopping") == 0) r.state = PLATFORM_WATCHER_STATE_STOPPING;
    else return false;
    if (!platform_watcher_record_is_valid(&r)) return false;
    *out = r; return true;
}

static bool identity_equal(const struct platform_watcher_file_identity *a,
                           const struct platform_watcher_file_identity *b)
{ return a->volume == b->volume && a->file_low == b->file_low &&
         a->file_high == b->file_high; }

bool platform_watcher_record_matches(const struct platform_watcher_record *r,
    const struct platform_watcher_record_binding *b)
{
    return platform_watcher_record_is_valid(r) && b &&
        fixed_hex(b->nonce, PLATFORM_WATCHER_RECORD_NONCE_HEX) &&
        fixed_hex(b->image_sha256, PLATFORM_WATCHER_RECORD_HASH_HEX) &&
        b->pid != 0 && b->start_token != 0 &&
        (b->mode == PLATFORM_WATCHER_MODE_VERIFY ||
         b->mode == PLATFORM_WATCHER_MODE_AUTO) &&
        path_valid(b->canonical_root) && identity_valid(&b->root_identity) &&
        path_valid(b->canonical_image) && identity_valid(&b->image_identity) &&
        b->image_size != 0 &&
        (b->state == PLATFORM_WATCHER_STATE_STARTING ||
         b->state == PLATFORM_WATCHER_STATE_READY ||
         b->state == PLATFORM_WATCHER_STATE_STOPPING) &&
        r->pid == b->pid && r->start_token == b->start_token &&
        r->mode == b->mode && strcmp(r->nonce,b->nonce) == 0 &&
        strcmp(r->canonical_root,b->canonical_root) == 0 &&
        identity_equal(&r->root_identity,&b->root_identity) &&
        strcmp(r->canonical_image,b->canonical_image) == 0 &&
        identity_equal(&r->image_identity,&b->image_identity) &&
        r->image_size == b->image_size &&
        strcmp(r->image_sha256,b->image_sha256) == 0 && r->state == b->state;
}
