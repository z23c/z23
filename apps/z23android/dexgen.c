/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* Host build tool: writes the classes.dex (format 035) that holds the one Java class the app needs,
 *
 *   public final class org.z23.nativeapp.NodeService extends android.app.Service {
 *       static { System.loadLibrary("z23android"); }
 *       public NodeService() { super(); }
 *       public IBinder onBind(Intent i) { return null; }
 *       public int onStartCommand(Intent i, int flags, int id) { return start(this, id); }
 *       private static native int start(Service service, int id);
 *   }
 *
 * The output is deterministic. Usage: dexgen <output.dex> */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { DEX_MAX = 2048, HEADER_SIZE = 0x70, NO_INDEX = -1 };

/* String ids, in modified-UTF-8 byte order as the format requires. */
enum {
    S_CLINIT, S_INIT, S_I, S_ILI, S_ILII, S_LL, S_SERVICE, S_INTENT, S_IBINDER, S_STRING, S_SYSTEM,
    S_NODE, S_V, S_VL, S_LOADLIB, S_ONBIND, S_ONSTART, S_START, S_LIB, S_COUNT
};
static const char *const strings[S_COUNT] = {
    "<clinit>", "<init>", "I", "ILI", "ILII", "LL", "Landroid/app/Service;", "Landroid/content/Intent;",
    "Landroid/os/IBinder;", "Ljava/lang/String;", "Ljava/lang/System;", "Lorg/z23/nativeapp/NodeService;",
    "V", "VL", "loadLibrary", "onBind", "onStartCommand", "start", "z23android"
};

/* Type ids, ascending by string id. */
enum { T_I, T_SERVICE, T_INTENT, T_IBINDER, T_STRING, T_SYSTEM, T_NODE, T_V, T_COUNT };
static const uint8_t type_string[T_COUNT] = {
    S_I, S_SERVICE, S_INTENT, S_IBINDER, S_STRING, S_SYSTEM, S_NODE, S_V
};

/* Parameter lists referenced by prototypes. */
enum { L_NONE = -1, L_STRING, L_SERVICE_I, L_INTENT, L_INTENT_II, L_COUNT };
static const struct { uint8_t count; uint8_t types[3]; } lists[L_COUNT] = {
    { 1, { T_STRING } }, { 2, { T_SERVICE, T_I } }, { 1, { T_INTENT } }, { 3, { T_INTENT, T_I, T_I } }
};

/* Prototypes, ascending by return type, then parameter types. */
enum { P_I_SERVICE_I, P_I_INTENT_II, P_IBINDER_INTENT, P_V, P_V_STRING, P_COUNT };
static const struct { uint8_t shorty, ret; int8_t list; } protos[P_COUNT] = {
    { S_ILI, T_I, L_SERVICE_I }, { S_ILII, T_I, L_INTENT_II }, { S_LL, T_IBINDER, L_INTENT },
    { S_V, T_V, L_NONE }, { S_VL, T_V, L_STRING }
};

/* Methods, ascending by class, then name, then prototype. */
enum { M_SERVICE_INIT, M_LOADLIB, M_CLINIT, M_INIT, M_ONBIND, M_ONSTART, M_START, M_COUNT };
static const struct { uint8_t cls, proto, name; } methods[M_COUNT] = {
    { T_SERVICE, P_V, S_INIT }, { T_SYSTEM, P_V_STRING, S_LOADLIB }, { T_NODE, P_V, S_CLINIT },
    { T_NODE, P_V, S_INIT }, { T_NODE, P_IBINDER_INTENT, S_ONBIND }, { T_NODE, P_I_INTENT_II, S_ONSTART },
    { T_NODE, P_I_SERVICE_I, S_START }
};

/* Dalvik bytecode. */
static const uint16_t code_clinit[] = { 0x001a, S_LIB, 0x1071, M_LOADLIB, 0x0000, 0x000e };
static const uint16_t code_init[] = { 0x1070, M_SERVICE_INIT, 0x0000, 0x000e };
static const uint16_t code_onbind[] = { 0x0012, 0x0011 };
static const uint16_t code_onstart[] = { 0x2071, M_START, 0x0041, 0x000a, 0x000f };
enum { C_CLINIT, C_INIT, C_ONBIND, C_ONSTART, C_COUNT };
static const struct { uint16_t regs, ins, outs, units; const uint16_t *insns; } codes[C_COUNT] = {
    { 1, 0, 1, 6, code_clinit }, { 1, 1, 1, 4, code_init },
    { 3, 2, 0, 2, code_onbind }, { 5, 4, 2, 5, code_onstart }
};

enum { ACC_PUBLIC = 0x1, ACC_PRIVATE = 0x2, ACC_STATIC = 0x8, ACC_FINAL = 0x10, ACC_NATIVE = 0x100,
       ACC_CONSTRUCTOR = 0x10000 };

/* Output cursor over a fixed buffer; overflow is sticky. */
struct out { uint8_t b[DEX_MAX]; uint32_t n; bool over; };

static void put(struct out *o, uint32_t v, unsigned bytes)
{
    if (o->n + bytes > DEX_MAX) { o->over = true; return; }
    for (unsigned i = 0; i < bytes; ++i) o->b[o->n++] = (uint8_t)(v >> (8 * i));
}
static void patch32(struct out *o, uint32_t at, uint32_t v)
{
    if (at + 4 > o->n) { o->over = true; return; }
    for (unsigned i = 0; i < 4; ++i) o->b[at + i] = (uint8_t)(v >> (8 * i));
}
static void uleb(struct out *o, uint32_t v)
{
    do { uint8_t byte = v & 0x7f; v >>= 7; put(o, byte | (v ? 0x80 : 0), 1); } while (v);
}
static void align4(struct out *o) { put(o, 0, (4 - (o->n & 3)) & 3); }

uint32_t dexgen_adler32(const uint8_t *p, size_t n)
{
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < n; ++i) { a = (a + p[i]) % 65521; b = (b + a) % 65521; }
    return b << 16 | a;
}

static uint32_t rol(uint32_t v, unsigned s) { return v << s | v >> (32 - s); }
static void sha1_block(uint32_t h[5], const uint8_t *p)
{
    uint32_t w[80], a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 16; ++i) w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 80; ++i) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    for (int i = 0; i < 80; ++i) {
        uint32_t f = i < 20 ? (b & c) | (~b & d) : i < 40 || i >= 60 ? b ^ c ^ d : (b & c) | (b & d) | (c & d);
        uint32_t k = i < 20 ? 0x5a827999 : i < 40 ? 0x6ed9eba1 : i < 60 ? 0x8f1bbcdc : 0xca62c1d6;
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}
void dexgen_sha1(const uint8_t *p, size_t n, uint8_t digest[20])
{
    uint32_t h[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
    size_t whole = n & ~(size_t)63;
    for (size_t i = 0; i < whole; i += 64) sha1_block(h, p + i);
    uint8_t tail[128] = { 0 };
    size_t rest = n - whole, len = rest < 56 ? 64 : 128;
    memcpy(tail, p + whole, rest);
    tail[rest] = 0x80;
    for (int i = 0; i < 8; ++i) tail[len - 1 - i] = (uint8_t)(((uint64_t)n * 8) >> (8 * i));
    for (size_t i = 0; i < len; i += 64) sha1_block(h, tail + i);
    for (int i = 0; i < 20; ++i) digest[i] = (uint8_t)(h[i / 4] >> (24 - 8 * (i % 4)));
}

static void emit_ids(struct out *o, uint32_t at[2], uint32_t params[P_COUNT])
{
    for (int i = 0; i < S_COUNT; ++i) put(o, 0, 4);
    at[0] = o->n;
    for (int i = 0; i < T_COUNT; ++i) put(o, type_string[i], 4);
    at[1] = o->n;
    for (int i = 0; i < P_COUNT; ++i) {
        put(o, protos[i].shorty, 4); put(o, protos[i].ret, 4);
        params[i] = o->n; put(o, 0, 4);
    }
}
static void emit_strings(struct out *o, uint32_t ids_at)
{
    for (int i = 0; i < S_COUNT; ++i) {
        patch32(o, ids_at + 4 * (uint32_t)i, o->n);
        size_t len = strlen(strings[i]);
        uleb(o, (uint32_t)len);
        for (size_t j = 0; j <= len; ++j) put(o, (uint8_t)strings[i][j], 1);
    }
}
static void emit_lists(struct out *o, const uint32_t params[P_COUNT], uint32_t *first)
{
    uint32_t at[L_COUNT];
    align4(o); *first = o->n;
    for (int i = 0; i < L_COUNT; ++i) {
        align4(o); at[i] = o->n;
        put(o, lists[i].count, 4);
        for (int j = 0; j < lists[i].count; ++j) put(o, lists[i].types[j], 2);
    }
    for (int i = 0; i < P_COUNT; ++i)
        if (protos[i].list != L_NONE) patch32(o, params[i], at[protos[i].list]);
}
static void emit_code(struct out *o, uint32_t at[C_COUNT])
{
    for (int i = 0; i < C_COUNT; ++i) {
        align4(o); at[i] = o->n;
        put(o, codes[i].regs, 2); put(o, codes[i].ins, 2); put(o, codes[i].outs, 2); put(o, 0, 2);
        put(o, 0, 4); put(o, codes[i].units, 4);
        for (int j = 0; j < codes[i].units; ++j) put(o, codes[i].insns[j], 2);
    }
}
/* Direct methods then virtual methods, each as method-index delta, flags and code offset. */
static void emit_class_data(struct out *o, const uint32_t code[C_COUNT])
{
    static const struct { uint8_t method; uint32_t flags; int8_t code; } direct[] = {
        { M_CLINIT, ACC_STATIC | ACC_CONSTRUCTOR, C_CLINIT }, { M_INIT, ACC_PUBLIC | ACC_CONSTRUCTOR, C_INIT },
        { M_START, ACC_PRIVATE | ACC_STATIC | ACC_NATIVE, -1 }
    }, virt[] = { { M_ONBIND, ACC_PUBLIC, C_ONBIND }, { M_ONSTART, ACC_PUBLIC, C_ONSTART } };
    uleb(o, 0); uleb(o, 0); uleb(o, 3); uleb(o, 2);
    for (int pass = 0; pass < 2; ++pass) {
        const typeof(direct[0]) *list = pass ? virt : direct;
        int count = pass ? 2 : 3, previous = 0;
        for (int i = 0; i < count; ++i) {
            uleb(o, (uint32_t)(list[i].method - previous)); previous = list[i].method;
            uleb(o, list[i].flags); uleb(o, list[i].code < 0 ? 0 : code[list[i].code]);
        }
    }
}
struct section { uint16_t type; uint32_t size, offset; };
static void emit_map(struct out *o, const struct section *s, int count)
{
    align4(o);
    put(o, (uint32_t)count, 4);
    for (int i = 0; i < count; ++i) {
        put(o, s[i].type, 2); put(o, 0, 2); put(o, s[i].size, 4); put(o, s[i].offset, 4);
    }
}
/* s holds the header, string, type, prototype and method sections in that order. */
static void emit_header(struct out *o, const struct section *s, uint32_t map, uint32_t class_def, uint32_t data)
{
    memcpy(o->b, "dex\n035", 8);
    patch32(o, 32, o->n); patch32(o, 36, HEADER_SIZE); patch32(o, 40, 0x12345678);
    patch32(o, 52, map);
    for (int i = 0; i < 2; ++i) { patch32(o, 56 + 8 * (uint32_t)i, s[i + 1].size); patch32(o, 60 + 8 * (uint32_t)i, s[i + 1].offset); }
    patch32(o, 72, s[3].size); patch32(o, 76, s[3].offset);
    patch32(o, 88, s[4].size); patch32(o, 92, s[4].offset);
    patch32(o, 96, 1); patch32(o, 100, class_def);
    patch32(o, 104, o->n - data); patch32(o, 108, data);
}

/* Builds the dex into out and returns its size, or 0 when cap is too small. */
size_t dexgen_build(uint8_t *out, size_t cap)
{
    static struct out o;
    uint32_t params[P_COUNT], code[C_COUNT], ids[2], lists_at, class_data;
    memset(&o, 0, sizeof(o));
    for (int i = 0; i < HEADER_SIZE; ++i) put(&o, 0, 1);
    uint32_t string_ids = o.n;
    emit_ids(&o, ids, params);
    uint32_t method_ids = o.n;
    for (int i = 0; i < M_COUNT; ++i) { put(&o, methods[i].cls, 2); put(&o, methods[i].proto, 2); put(&o, methods[i].name, 4); }
    uint32_t class_def = o.n;
    put(&o, T_NODE, 4); put(&o, ACC_PUBLIC | ACC_FINAL, 4); put(&o, T_SERVICE, 4); put(&o, 0, 4);
    put(&o, (uint32_t)NO_INDEX, 4); put(&o, 0, 4); put(&o, 0, 4); put(&o, 0, 4);
    uint32_t data = o.n, string_data = o.n;
    emit_strings(&o, string_ids);
    emit_lists(&o, params, &lists_at);
    emit_code(&o, code);
    class_data = o.n;
    emit_class_data(&o, code);
    patch32(&o, class_def + 24, class_data);
    uint32_t map = (o.n + 3) & ~3u;
    const struct section sections[] = {
        { 0x0000, 1, 0 }, { 0x0001, S_COUNT, string_ids }, { 0x0002, T_COUNT, ids[0] },
        { 0x0003, P_COUNT, ids[1] }, { 0x0005, M_COUNT, method_ids }, { 0x0006, 1, class_def },
        { 0x2002, S_COUNT, string_data }, { 0x1001, L_COUNT, lists_at }, { 0x2001, C_COUNT, code[0] },
        { 0x2000, 1, class_data }, { 0x1000, 1, map }
    };
    emit_map(&o, sections, (int)(sizeof(sections) / sizeof(sections[0])));
    emit_header(&o, sections, map, class_def, data);
    if (o.over || o.n > cap) return 0;
    dexgen_sha1(o.b + 32, o.n - 32, o.b + 12);
    patch32(&o, 8, dexgen_adler32(o.b + 12, o.n - 12));
    memcpy(out, o.b, o.n);
    return o.n;
}

#ifndef DEXGEN_NO_MAIN
int main(int argc, char **argv)
{
    static uint8_t dex[DEX_MAX];
    if (argc != 2) { fputs("usage: dexgen <output.dex>\n", stderr); return 2; }
    size_t n = dexgen_build(dex, sizeof(dex));
    FILE *f = n ? fopen(argv[1], "wb") : NULL;
    bool ok = f && fwrite(dex, 1, n, f) == n;
    if (f && fclose(f) != 0) ok = false;
    if (!ok) { fprintf(stderr, "dexgen: cannot write %s\n", argv[1]); return 1; }
    return 0;
}
#endif
