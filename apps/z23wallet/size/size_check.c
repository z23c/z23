/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the z23-wallet size budget. Reads the section table of the built
 * wallet (PE32+ or ELF64, no external tools), compares the file size with the
 * budget recorded for this toolchain in apps/z23wallet/size/budget.tsv and,
 * when it is over, says by how many bytes and which sections grew against the
 * reference sizes recorded beside the budget. A toolchain with no recorded
 * budget is reported, not failed: sizes are only comparable on the reference
 * toolchain that set them. Every offset, count and length read from the image
 * is checked in subtraction form, so no header value can wrap a bound.
 *   z23-wallet-size-check <binary> <budget.tsv> <toolchain-key>
 *   z23-wallet-size-check --rows <binary> <toolchain-key>  (print the rows of a new budget)
 *   z23-wallet-size-check --selftest
 * Exit: 0 within budget (or no budget for this toolchain), 1 over budget,
 * 2 usage, unreadable or malformed input. */
#define _POSIX_C_SOURCE 200809L /* strnlen */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SECTIONS 64u
#define NAME_CAP 32u
#define LINE_CAP 256u

struct section { char name[NAME_CAP]; uint64_t bytes; };
struct image { uint64_t file_bytes; size_t n; struct section s[MAX_SECTIONS]; };
struct budget { uint64_t limit; size_t n; struct section ref[MAX_SECTIONS]; bool found; };

static uint32_t rd16(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8; }
static uint32_t rd32(const uint8_t *p) { return rd16(p) | rd16(p + 2) << 16; }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32; }

/* [off, off + n) lies inside a buffer of len bytes, without computing off + n. */
static bool in_range(uint64_t off, uint64_t n, uint64_t len) { return off <= len && n <= len - off; }

static void add_section(struct image *im, const char *name, size_t name_len, uint64_t bytes)
{
    if (im->n >= MAX_SECTIONS || !bytes) return;
    struct section *s = &im->s[im->n++];
    size_t k = name_len < NAME_CAP - 1 ? name_len : NAME_CAP - 1;
    memcpy(s->name, name, k);
    s->name[k] = 0;
    s->bytes = bytes;
}

/* A section name longer than 8 bytes is "/<offset>" into the COFF string
 * table that follows the symbol table (.gnu_debuglink is one). A long name
 * that points outside the file makes the image malformed. */
static bool pe_add(const uint8_t *d, size_t len, uint64_t strtab, const uint8_t *hdr, struct image *im)
{
    const char *name = (const char *)hdr;
    size_t name_len = strnlen(name, 8);
    if (name[0] == '/') {
        char digits[8] = { 0 };
        memcpy(digits, name + 1, 7);
        uint64_t off = strtoull(digits, NULL, 10);
        if (!strtab || off >= len - strtab) return false; /* strtab < len is checked by the caller */
        name = (const char *)d + strtab + off;
        name_len = strnlen(name, len - (size_t)(strtab + off));
    }
    add_section(im, name, name_len, rd32(hdr + 16));
    return true;
}

/* PE32+: the bytes each section occupies in the file (SizeOfRawData). */
static bool parse_pe(const uint8_t *d, size_t len, struct image *im)
{
    if (len < 0x40) return false;
    uint64_t pe = rd32(d + 0x3c);
    if (!in_range(pe, 24, len) || memcmp(d + pe, "PE\0\0", 4)) return false;
    uint64_t nsec = rd16(d + pe + 6), opt = rd16(d + pe + 20);
    uint64_t symtab = rd32(d + pe + 12), nsym = rd32(d + pe + 16);
    if (!in_range(pe + 24, opt, len)) return false;
    uint64_t at = pe + 24 + opt;
    if (!in_range(at, nsec * 40, len)) return false;
    /* No string table, or one past the end: then no long name may be used. */
    uint64_t strtab = symtab && in_range(symtab, nsym * 18, len) ? symtab + nsym * 18 : 0;
    if (strtab >= len) strtab = 0;
    for (uint64_t i = 0; i < nsec; i++, at += 40)
        if (!pe_add(d, len, strtab, d + at, im)) return false;
    return true;
}

/* ELF64 little-endian: every section that occupies file bytes (not NOBITS). */
static bool parse_elf(const uint8_t *d, size_t len, struct image *im)
{
    if (len < 64 || d[4] != 2 || d[5] != 1) return false;
    uint64_t shoff = rd64(d + 0x28);
    uint64_t shentsize = rd16(d + 0x3a), shnum = rd16(d + 0x3c), shstrndx = rd16(d + 0x3e);
    if (shentsize < 64 || shstrndx >= shnum || !in_range(shoff, shnum * shentsize, len)) return false;
    const uint8_t *strh = d + shoff + shstrndx * shentsize;
    uint64_t stroff = rd64(strh + 0x18), strsz = rd64(strh + 0x20);
    if (!in_range(stroff, strsz, len)) return false;
    for (uint64_t i = 1; i < shnum; i++) {
        const uint8_t *h = d + shoff + i * shentsize;
        uint64_t name = rd32(h);
        if (name >= strsz) return false;
        if (rd32(h + 4) == 8) continue; /* SHT_NOBITS: .bss, .tbss */
        const char *nm = (const char *)d + stroff + name;
        add_section(im, nm, strnlen(nm, (size_t)(strsz - name)), rd64(h + 0x20));
    }
    return true;
}

static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    uint8_t *d = NULL;
    if (fseek(f, 0, SEEK_END) == 0) {
        long n = ftell(f);
        d = n > 0 ? malloc((size_t)n) : NULL;
        if (d && (fseek(f, 0, SEEK_SET) != 0 || fread(d, 1, (size_t)n, f) != (size_t)n)) {
            free(d);
            d = NULL;
        }
        *len = d ? (size_t)n : 0;
    }
    fclose(f);
    return d;
}

static bool parse_any(const uint8_t *d, size_t len, struct image *im)
{
    memset(im, 0, sizeof(*im));
    im->file_bytes = len;
    if (len > 4 && !memcmp(d, "\x7f" "ELF", 4)) return parse_elf(d, len, im);
    if (len > 2 && d[0] == 'M' && d[1] == 'Z') return parse_pe(d, len, im);
    return false;
}

static bool load_image(const char *path, struct image *im)
{
    size_t len = 0;
    uint8_t *d = slurp(path, &len);
    if (!d) {
        fprintf(stderr, "z23-wallet-size-check: cannot read %s (build it first: make z23-wallet)\n", path);
        return false;
    }
    bool ok = parse_any(d, len, im);
    free(d);
    if (!ok) fprintf(stderr, "z23-wallet-size-check: %s is not a well-formed PE32+ or ELF64 image\n", path);
    return ok;
}

/* A whole decimal number, nothing else. */
static bool parse_u64(const char *v, uint64_t *out)
{
    char *end = NULL;
    if (!v || v[0] < '0' || v[0] > '9') return false;
    *out = strtoull(v, &end, 10);
    return end && !*end;
}

/* One budget row: key TAB name TAB bytes. "budget" is the file-size limit;
 * any other name is a section's reference size when the budget was set.
 * False on a malformed row of this key: a bad number must never read as 0,
 * which would silently mean "no budget". */
static bool budget_row(char *line, const char *key, struct budget *b)
{
    line[strcspn(line, "\r\n")] = 0;
    char *k = strtok(line, "\t"), *name = strtok(NULL, "\t"), *v = strtok(NULL, "\t");
    if (!k || k[0] == '#' || strcmp(k, key)) return true;
    uint64_t bytes = 0;
    if (!name || strlen(name) >= NAME_CAP || !parse_u64(v, &bytes) || strtok(NULL, "\t")) return false;
    b->found = true;
    if (!strcmp(name, "budget")) b->limit = bytes;
    else if (b->n < MAX_SECTIONS) {
        snprintf(b->ref[b->n].name, NAME_CAP, "%s", name);
        b->ref[b->n++].bytes = bytes;
    }
    return true;
}

static bool load_budget(const char *path, const char *key, struct budget *b)
{
    FILE *f = fopen(path, "r");
    memset(b, 0, sizeof(*b));
    if (!f) {
        fprintf(stderr, "z23-wallet-size-check: cannot read the budget table %s\n", path);
        return false;
    }
    char line[LINE_CAP];
    unsigned lineno = 0;
    bool ok = true;
    while (ok && fgets(line, sizeof(line), f)) {
        lineno++;
        bool whole = strchr(line, '\n') || feof(f);
        ok = whole && budget_row(line, key, b);
    }
    fclose(f);
    if (!ok)
        fprintf(stderr, "z23-wallet-size-check: %s line %u is malformed (want key<TAB>name<TAB>decimal bytes, "
                "under %u bytes)\n", path, lineno, LINE_CAP);
    return ok;
}

static uint64_t ref_bytes(const struct budget *b, const char *name)
{
    for (size_t i = 0; i < b->n; i++)
        if (!strcmp(b->ref[i].name, name)) return b->ref[i].bytes;
    return 0;
}

static void report_growth(const struct image *im, const struct budget *b, FILE *out)
{
    bool any = false;
    for (size_t i = 0; i < im->n; i++) {
        uint64_t ref = ref_bytes(b, im->s[i].name);
        if (im->s[i].bytes <= ref) continue;
        fprintf(out, "  %-14s +%llu bytes (reference %llu, now %llu)\n", im->s[i].name,
                (unsigned long long)(im->s[i].bytes - ref), (unsigned long long)ref,
                (unsigned long long)im->s[i].bytes);
        any = true;
    }
    if (!any) fprintf(out, "  no section grew against the reference: the budget itself was lowered\n");
}

/* No budget for this toolchain: report the file size only (any format). */
static int report_unbudgeted(const char *bin, const char *table, const char *key, FILE *out)
{
    size_t len = 0;
    uint8_t *d = slurp(bin, &len);
    if (!d) {
        fprintf(stderr, "z23-wallet-size-check: cannot read %s (build it first: make z23-wallet)\n", bin);
        return 2;
    }
    free(d);
    fprintf(out, "z23-wallet-size-check: %llu bytes; no budget is recorded for toolchain %s in %s, "
            "so nothing is enforced here (budgets hold only on the toolchain that set them)\n",
            (unsigned long long)len, key, table);
    return 0;
}

static int check(const char *bin, const char *table, const char *key, FILE *out)
{
    struct image im;
    struct budget b;
    if (!load_budget(table, key, &b)) return 2;
    if (!b.found || !b.limit) return report_unbudgeted(bin, table, key, out);
    if (!load_image(bin, &im)) return 2;
    if (im.file_bytes <= b.limit) {
        fprintf(out, "z23-wallet-size-check: %llu bytes, budget %llu on %s, %llu bytes of headroom\n",
                (unsigned long long)im.file_bytes, (unsigned long long)b.limit, key,
                (unsigned long long)(b.limit - im.file_bytes));
        return 0;
    }
    fprintf(out, "z23-wallet-size-check: FAIL %s is %llu bytes over its %llu-byte budget on %s (%llu bytes).\n"
            "Sections that grew against the reference build:\n", bin,
            (unsigned long long)(im.file_bytes - b.limit), (unsigned long long)b.limit, key,
            (unsigned long long)im.file_bytes);
    report_growth(&im, &b, out);
    fprintf(out, "Shrink the change, or raise the budget in %s with the measurement that justifies it.\n", table);
    return 1;
}

/* ---- self test: synthetic PE and ELF images of known layout ---- */

static void wr16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void wr32(uint8_t *p, uint32_t v) { wr16(p, v & 0xffffu); wr16(p + 2, v >> 16); }
static void wr64(uint8_t *p, uint64_t v) { wr32(p, (uint32_t)v); wr32(p + 4, (uint32_t)(v >> 32)); }

static size_t fake_pe(uint8_t *d, uint32_t text, uint32_t rdata)
{
    memset(d, 0, 1024);
    d[0] = 'M'; d[1] = 'Z';
    wr32(d + 0x3c, 0x80);
    memcpy(d + 0x80, "PE\0\0", 4);
    wr16(d + 0x86, 4);
    wr32(d + 0x8c, 0x300); /* symbol table pointer, no symbols: the string table starts there */
    wr16(d + 0x94, 0xf0);
    uint8_t *s = d + 0x80 + 24 + 0xf0;
    memcpy(s, ".text", 5); wr32(s + 16, text);
    memcpy(s + 40, ".rdata", 6); wr32(s + 56, rdata);
    memcpy(s + 80, ".bss", 4); wr32(s + 96, 0);
    memcpy(s + 120, "/4", 2); wr32(s + 136, 512);
    memcpy(d + 0x304, ".gnu_debuglink", 15);
    return 1024;
}

static size_t fake_elf(uint8_t *d, uint64_t text)
{
    static const char names[] = "\0.text\0.bss\0.shstrtab";
    memset(d, 0, 1024);
    memcpy(d, "\x7f" "ELF", 4);
    d[4] = 2; d[5] = 1;
    wr64(d + 0x28, 256);
    wr16(d + 0x3a, 64); wr16(d + 0x3c, 4); wr16(d + 0x3e, 3);
    memcpy(d + 128, names, sizeof(names));
    uint8_t *h = d + 256;
    wr32(h + 64, 1); wr32(h + 68, 1); wr64(h + 64 + 0x20, text);
    wr32(h + 128, 7); wr32(h + 132, 8); wr64(h + 128 + 0x20, 4096);
    wr32(h + 192, 12); wr32(h + 196, 3); wr64(h + 192 + 0x18, 128); wr64(h + 192 + 0x20, sizeof(names));
    return 1024;
}

/* Parse the first len bytes from an exact-size heap copy, so a sanitizer sees
 * any read past the end of the image. */
static bool parse_exact(const uint8_t *d, size_t len)
{
    uint8_t *copy = malloc(len);
    struct image *im = malloc(sizeof(*im));
    bool ok = copy && im;
    if (ok) {
        memcpy(copy, d, len);
        ok = parse_any(copy, len, im);
    }
    free(copy);
    free(im);
    return ok;
}

static bool write_file(const char *path, const void *d, size_t n)
{
    FILE *f = fopen(path, "wb");
    bool ok = f && fwrite(d, 1, n, f) == n;
    return (f ? fclose(f) == 0 : false) && ok;
}

static int expect(const char *what, bool ok)
{
    printf("  %s... %s\n", what, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static int selftest_parse(void)
{
    uint8_t d[1024];
    struct image im;
    int bad = 0;
    bad += expect("PE sections: raw sizes, .bss occupies no file bytes, long names resolved",
                  parse_any(d, fake_pe(d, 4096, 512), &im) && im.n == 3 && im.s[0].bytes == 4096 &&
                  !strcmp(im.s[1].name, ".rdata") && !strcmp(im.s[2].name, ".gnu_debuglink"));
    bad += expect("ELF sections are named from .shstrtab and NOBITS is skipped",
                  parse_any(d, fake_elf(d, 3000), &im) && im.n == 2 && !strcmp(im.s[0].name, ".text") &&
                  im.s[0].bytes == 3000);
    bad += expect("a truncated or foreign header is refused", !parse_exact(d, 10) && (d[0] = 'X', !parse_exact(d, 1024)));
    return bad;
}

static int selftest_hostile(void)
{
    uint8_t d[1024];
    int bad = 0;
    fake_elf(d, 3000);
    wr64(d + 0x28, UINT64_C(0xFFFFFFFFFFFFFF00));
    bad += expect("an ELF section-table offset that wraps is refused", !parse_exact(d, 128));
    fake_elf(d, 3000);
    wr64(d + 256 + 192 + 0x18, UINT64_C(0xFFFFFFFFFFFFFFF0));
    bad += expect("an ELF string-table offset that wraps is refused", !parse_exact(d, 1024));
    bad += expect("a truncated ELF section table is refused", (fake_elf(d, 3000), !parse_exact(d, 300)));
    fake_elf(d, 3000);
    wr32(d + 256 + 64, 500);
    bad += expect("an ELF section name outside .shstrtab is refused", !parse_exact(d, 1024));
    bad += expect("a truncated PE section table is refused", (fake_pe(d, 4096, 512), !parse_exact(d, 0x220)));
    fake_pe(d, 4096, 512);
    wr32(d + 0x3c, 0xFFFFFFF0u);
    bad += expect("a PE header offset past the end is refused", !parse_exact(d, 1024));
    fake_pe(d, 4096, 512);
    memcpy(d + 0x80 + 24 + 0xf0 + 120, "/9999", 5);
    bad += expect("a PE long name outside the string table is refused", !parse_exact(d, 1024));
    return bad;
}

static int selftest_budget(const char *dir)
{
    char bin[512], tab[512];
    uint8_t d[1024];
    snprintf(bin, sizeof(bin), "%s/size_check_selftest.bin", dir);
    snprintf(tab, sizeof(tab), "%s/size_check_selftest.tsv", dir);
    static const char rows[] = "# key\tname\tbytes\nref\tbudget\t1000\nref\t.text\t2048\nref\t.rdata\t512\n"
                               "roomy\tbudget\t4096\nbad\tbudget\t12k\n";
    if (!write_file(bin, d, fake_pe(d, 4096, 512)) || !write_file(tab, rows, sizeof(rows) - 1)) {
        printf("  cannot write self-test files in %s... FAIL\n", dir);
        return 1;
    }
    FILE *sink = tmpfile();
    FILE *o = sink ? sink : stdout;
    int bad = 0;
    bad += expect("an image over its budget fails", check(bin, tab, "ref", o) == 1);
    bad += expect("an image within its budget passes", check(bin, tab, "roomy", o) == 0);
    bad += expect("a toolchain without a budget is reported, not failed", check(bin, tab, "other", o) == 0);
    bad += expect("a missing binary is a usage error", check("/nonexistent/zw.bin", tab, "ref", o) == 2);
    bad += expect("a malformed budget number is refused, never read as 0", check(bin, tab, "bad", o) == 2);
    char longrow[400];
    memset(longrow, 'x', sizeof(longrow));
    memcpy(longrow, "ref\t", 4);
    longrow[sizeof(longrow) - 1] = '\n';
    bad += expect("a row longer than the line buffer is refused, not split",
                  write_file(tab, longrow, sizeof(longrow)) && check(bin, tab, "ref", o) == 2);
    if (sink) fclose(sink);
    remove(bin);
    remove(tab);
    return bad;
}

/* The rows a new budget is recorded from: the file size and every section. */
static int list_rows(const char *bin, const char *key)
{
    struct image im;
    if (!load_image(bin, &im)) return 2;
    printf("%s\tbudget\t%llu\n", key, (unsigned long long)im.file_bytes);
    for (size_t i = 0; i < im.n; i++) printf("%s\t%s\t%llu\n", key, im.s[i].name, (unsigned long long)im.s[i].bytes);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--selftest")) {
        const char *dir = getenv("TMPDIR");
        int bad = selftest_parse() + selftest_hostile() + selftest_budget(dir && dir[0] ? dir : ".");
        printf("z23-wallet-size-check selftest: %s\n", bad ? "FAIL" : "ok");
        return bad ? 1 : 0;
    }
    if (argc == 4 && !strcmp(argv[1], "--rows")) return list_rows(argv[2], argv[3]);
    if (argc != 4) {
        fprintf(stderr, "usage: z23-wallet-size-check <binary> <budget.tsv> <toolchain-key>\n"
                        "       z23-wallet-size-check --rows <binary> <toolchain-key>   (rows to record a budget)\n"
                        "       z23-wallet-size-check --selftest\n");
        return 2;
    }
    return check(argv[1], argv[2], argv[3], stdout);
}
