/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: boundary cases for the supervised-process native ELF image policy
 * (platform_supervised_image_capture). Each row builds a small image from one
 * valid base and moves exactly one field to, or just past, a limit, so a
 * comparison that drifts by one (or an operator that flips) changes the
 * accept/refuse verdict. Called from test_supervised_process.c. */
#include "test/test_core.h"
#include "platform/supervised_process.h"

#if defined(__linux__)
#include "sha3/sha3.h"

#include <elf.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#if defined(__x86_64__)
#define IMG_MACHINE EM_X86_64
#define IMG_LOADER "/lib64/ld-linux-x86-64.so.2"
#else
#define IMG_MACHINE EM_AARCH64
#define IMG_LOADER "/lib/ld-linux-aarch64.so.1"
#endif

enum {
    IMG_BUF = 0x13000,
    IMG_INTERP_OFF = 0x1000,
    IMG_DYN_OFF = 0x2000,
    IMG_MAX_PH = 160,
    IMG_STRSZ = 10
};
#define IMG_BASE_VADDR UINT64_C(0x400000)
#define IMG_DATA_VADDR UINT64_C(0x600000)

static uint8_t img_buffer[IMG_BUF];

struct img {
    uint8_t *bytes;
    size_t length;
    Elf64_Ehdr header;
    Elf64_Phdr ph[IMG_MAX_PH];
    unsigned phnum;
};

static Elf64_Phdr img_seg(uint32_t type, uint32_t flags, uint64_t vaddr,
                          uint64_t offset, uint64_t size, uint64_t align)
{
    return (Elf64_Phdr){.p_type = type, .p_flags = flags, .p_offset = offset,
        .p_vaddr = vaddr, .p_filesz = size, .p_memsz = size, .p_align = align};
}

static void img_add(struct img *m, Elf64_Phdr p)
{
    m->ph[m->phnum++] = p;
}

/* A valid static image: one RX load of 0x100 bytes at the base address with
 * the entry point 0x10 bytes in. */
static void img_begin(struct img *m, uint8_t *bytes, size_t length)
{
    memset(m, 0, sizeof(*m));
    m->bytes = bytes;
    m->length = length;
    memset(bytes, 0, length);
    m->header = (Elf64_Ehdr){.e_type = ET_EXEC, .e_machine = IMG_MACHINE,
        .e_version = EV_CURRENT, .e_entry = IMG_BASE_VADDR + 0x10,
        .e_phoff = sizeof(Elf64_Ehdr), .e_ehsize = sizeof(Elf64_Ehdr),
        .e_phentsize = sizeof(Elf64_Phdr)};
    memcpy(m->header.e_ident, ELFMAG, SELFMAG);
    m->header.e_ident[EI_CLASS] = ELFCLASS64;
    m->header.e_ident[EI_DATA] = ELFDATA2LSB;
    m->header.e_ident[EI_VERSION] = EV_CURRENT;
    img_add(m, img_seg(PT_LOAD, PF_R | PF_X, IMG_BASE_VADDR, 0, 0x100, 4096));
}

static enum platform_supervised_image_result img_capture(struct img *m)
{
    m->header.e_phnum = (uint16_t)m->phnum;
    memcpy(m->bytes, &m->header, sizeof(m->header));
    memcpy(m->bytes + sizeof(m->header), m->ph, m->phnum * sizeof(Elf64_Phdr));
    struct sha3_256_ctx hash;
    uint8_t digest[32];
    sha3_256_init(&hash);
    sha3_256_write(&hash, m->bytes, m->length);
    sha3_256_finalize(&hash, digest);
    int fd = -1;
    enum platform_supervised_image_result result =
        platform_supervised_image_capture(m->bytes, m->length, digest, &fd);
    if (fd >= 0)
        close(fd);
    return result;
}

/* Dynamic section plumbing. The table sits at IMG_DYN_OFF, the one string
 * "libc.so.6" directly after it, and a read-only data load maps both. */
struct dyn_plan {
    const Elf64_Dyn *entries;
    size_t count;
    size_t table;
    uint64_t data_size;
    bool interp;
};

static Elf64_Dyn dyn(int64_t tag, uint64_t value)
{
    return (Elf64_Dyn){.d_tag = tag, .d_un.d_val = value};
}

static Elf64_Dyn dyn_strtab(size_t table)
{
    return dyn(DT_STRTAB, IMG_DATA_VADDR + table * sizeof(Elf64_Dyn));
}

static void img_dynamic(struct img *m, const struct dyn_plan *p)
{
    memcpy(m->bytes + IMG_DYN_OFF, p->entries, p->count * sizeof(Elf64_Dyn));
    memcpy(m->bytes + IMG_DYN_OFF + p->table * sizeof(Elf64_Dyn), "libc.so.6", IMG_STRSZ);
    img_add(m, img_seg(PT_LOAD, PF_R, IMG_DATA_VADDR, IMG_DYN_OFF, p->data_size, 1));
    Elf64_Phdr d = img_seg(PT_DYNAMIC, PF_R, IMG_DATA_VADDR, IMG_DYN_OFF,
                           p->table * sizeof(Elf64_Dyn), 1);
    img_add(m, d);
    if (p->interp) {
        memcpy(m->bytes + IMG_INTERP_OFF, IMG_LOADER, sizeof(IMG_LOADER));
        img_add(m, img_seg(PT_INTERP, PF_R, 0, IMG_INTERP_OFF, sizeof(IMG_LOADER), 1));
    }
}

static void dyn_standard(struct img *m, size_t table, uint64_t strsz,
                         uint64_t data_size, bool interp)
{
    Elf64_Dyn e[] = {dyn_strtab(table), dyn(DT_STRSZ, strsz), dyn(DT_NEEDED, 0),
                     dyn(DT_NULL, 0)};
    struct dyn_plan p = {e, 4, table, data_size, interp};
    img_dynamic(m, &p);
}

/* ---- header and segment rows ---- */
static void row_base(struct img *m) { (void)m; }
static void row_type_dyn(struct img *m) { m->header.e_type = ET_DYN; }
static void row_type_rel(struct img *m) { m->header.e_type = ET_REL; }

static void row_note_at_end(struct img *m)
{
    img_add(m, img_seg(PT_NOTE, PF_R, 0, m->length, 0, 1));
}

static void row_note_past_end(struct img *m)
{
    img_add(m, img_seg(PT_NOTE, PF_R, 0, m->length + 1, 0, 1));
}

static void add_null_headers(struct img *m, unsigned count)
{
    for (unsigned i = 0; i < count; i++)
        img_add(m, (Elf64_Phdr){.p_type = PT_NULL});
}

static void row_phnum_128(struct img *m) { add_null_headers(m, 127); }
static void row_phnum_129(struct img *m) { add_null_headers(m, 128); }

static void row_stack_rw(struct img *m)
{
    img_add(m, img_seg(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 16));
}

static void row_stack_x(struct img *m)
{
    img_add(m, img_seg(PT_GNU_STACK, PF_R | PF_X, 0, 0, 0, 16));
}

static void row_static_bad_interp(struct img *m)
{
    img_add(m, img_seg(PT_INTERP, PF_R, 0, IMG_INTERP_OFF, 5, 1));
}

static void row_static_dynamic_empty(struct img *m)
{
    img_add(m, img_seg(PT_DYNAMIC, PF_R, 0, IMG_DYN_OFF, 0, 1));
}

static void row_static_dynamic_odd(struct img *m)
{
    img_add(m, img_seg(PT_DYNAMIC, PF_R, 0, IMG_DYN_OFF, 17, 1));
}

/* ---- load segment rows ---- */
static void row_r_adjacent(struct img *m)
{
    img_add(m, img_seg(PT_LOAD, PF_R, 0x500000, 0x1000, 0x10, 1));
    img_add(m, img_seg(PT_LOAD, PF_R, 0x500010, 0x1010, 0x10, 1));
}

static void row_r_adjacent_reversed(struct img *m)
{
    img_add(m, img_seg(PT_LOAD, PF_R, 0x500010, 0x1010, 0x10, 1));
    img_add(m, img_seg(PT_LOAD, PF_R, 0x500000, 0x1000, 0x10, 1));
}

static void row_r_overlap(struct img *m)
{
    img_add(m, img_seg(PT_LOAD, PF_R, 0x500000, 0x1000, 0x10, 1));
    img_add(m, img_seg(PT_LOAD, PF_R, 0x50000F, 0x100F, 0x10, 1));
}

static void row_rx_same_page(struct img *m)
{
    img_add(m, img_seg(PT_LOAD, PF_R | PF_X, 0x400800, 0x800, 0x10, 1));
}

/* Odd end addresses expose a page mask that is one short of the page. */
static void row_odd_page_overlap(struct img *m)
{
    m->ph[0].p_filesz = 1;
    m->ph[0].p_memsz = 1;
    m->header.e_entry = IMG_BASE_VADDR;
    img_add(m, img_seg(PT_LOAD, PF_R | PF_W, 0x400801, 0x801, 1, 1));
}

static void row_page_adjacent(struct img *m)
{
    m->ph[0].p_memsz = 0x1000;
    img_add(m, img_seg(PT_LOAD, PF_R | PF_W, 0x401000, 0x1000, 0x10, 1));
}

static void row_page_adjacent_reversed(struct img *m)
{
    row_page_adjacent(m);
    Elf64_Phdr first = m->ph[0];
    m->ph[0] = m->ph[1];
    m->ph[1] = first;
}

static void row_page_gap(struct img *m)
{
    m->ph[0].p_memsz = 0x1000;
    img_add(m, img_seg(PT_LOAD, PF_R | PF_W, 0x402000, 0x1000, 0x10, 1));
}

static void row_bad_filesz(struct img *m)
{
    Elf64_Phdr p = img_seg(PT_LOAD, PF_R, 0x500000, 0x1000, 0x20, 1);
    p.p_memsz = 0x10;
    img_add(m, p);
}

static void row_bad_write_exec(struct img *m)
{
    img_add(m, img_seg(PT_LOAD, PF_R | PF_W | PF_X, 0x500000, 0x1000, 0x10, 1));
}

static void row_bad_memsz_huge(struct img *m)
{
    Elf64_Phdr p = img_seg(PT_LOAD, PF_R, 0x500000, 0x1000, 0, 1);
    p.p_memsz = UINT64_MAX;
    img_add(m, p);
}

static void row_bad_vaddr_huge(struct img *m)
{
    Elf64_Phdr p = img_seg(PT_LOAD, PF_R, UINT64_MAX - 0x10, 0x1000, 0, 1);
    p.p_memsz = 0x20;
    img_add(m, p);
}

static void row_bad_align_two(struct img *m)
{
    img_add(m, img_seg(PT_LOAD, PF_R, 0x1001, 0x1000, 0x10, 2));
}

static void row_bad_align_three(struct img *m)
{
    img_add(m, img_seg(PT_LOAD, PF_R, 0x1000, 0x1000, 0x10, 3));
}

static void row_bad_align_page(struct img *m)
{
    img_add(m, img_seg(PT_LOAD, PF_R, 0x500100, 0x1000, 0x10, 4096));
}

/* The largest memory size and highest address the geometry check admits. */
static void row_memsz_max(struct img *m)
{
    m->ph[0].p_vaddr = 0;
    m->ph[0].p_memsz = UINT64_MAX - (uint64_t)sysconf(_SC_PAGESIZE);
    m->header.e_entry = 0x10;
}

static void row_vaddr_max(struct img *m)
{
    uint64_t vaddr = UINT64_MAX - 0x100 - (uint64_t)sysconf(_SC_PAGESIZE);
    m->ph[0].p_vaddr = vaddr;
    m->ph[0].p_align = 1;
    m->header.e_entry = vaddr;
}

static void row_entry_last_byte(struct img *m) { m->header.e_entry = IMG_BASE_VADDR + 0xFF; }
static void row_entry_past_end(struct img *m) { m->header.e_entry = IMG_BASE_VADDR + 0x100; }

/* ---- dynamic section rows ---- */
static void row_dyn_tight(struct img *m)
{
    dyn_standard(m, 4, IMG_STRSZ, 4 * sizeof(Elf64_Dyn) + IMG_STRSZ, true);
}

static void row_dyn_no_interp(struct img *m)
{
    dyn_standard(m, 4, IMG_STRSZ, 4 * sizeof(Elf64_Dyn) + IMG_STRSZ, false);
}

static void dyn_five(struct img *m, Elf64_Dyn third, Elf64_Dyn fourth, bool interp)
{
    Elf64_Dyn e[] = {dyn_strtab(5), dyn(DT_STRSZ, IMG_STRSZ), third, fourth, dyn(DT_NULL, 0)};
    struct dyn_plan p = {e, 5, 5, 5 * sizeof(Elf64_Dyn) + IMG_STRSZ, interp};
    img_dynamic(m, &p);
}

static void row_dyn_flags_bind_now(struct img *m)
{
    dyn_five(m, dyn(DT_NEEDED, 0), dyn(DT_FLAGS, DF_BIND_NOW), true);
}

static void row_dyn_flags_textrel(struct img *m)
{
    dyn_five(m, dyn(DT_NEEDED, 0), dyn(DT_FLAGS, DF_TEXTREL), true);
}

static void row_dyn_two_needed(struct img *m)
{
    dyn_five(m, dyn(DT_NEEDED, 0), dyn(DT_NEEDED, 0), true);
}

static void row_dyn_no_needed_interp(struct img *m)
{
    dyn_five(m, dyn(DT_NULL, 0), dyn(DT_NULL, 0), true);
}

static void row_dyn_needed_first(struct img *m)
{
    Elf64_Dyn e[] = {dyn(DT_NEEDED, 0), dyn_strtab(5), dyn(DT_STRSZ, IMG_STRSZ),
                     dyn(DT_NEEDED, 0), dyn(DT_NULL, 0)};
    struct dyn_plan p = {e, 5, 5, 5 * sizeof(Elf64_Dyn) + IMG_STRSZ, true};
    img_dynamic(m, &p);
}

static void row_dyn_static_pie(struct img *m)
{
    Elf64_Dyn e[] = {dyn_strtab(3), dyn(DT_STRSZ, IMG_STRSZ), dyn(DT_NULL, 0)};
    struct dyn_plan p = {e, 3, 3, 3 * sizeof(Elf64_Dyn) + IMG_STRSZ, false};
    img_dynamic(m, &p);
}

static void row_dyn_second_dynamic(struct img *m)
{
    row_dyn_tight(m);
    img_add(m, m->ph[2]);
}

static void row_dyn_strsz_max(struct img *m)
{
    dyn_standard(m, 4, 65536, 4 * sizeof(Elf64_Dyn) + 65536, true);
}

static void row_dyn_strsz_over(struct img *m)
{
    dyn_standard(m, 4, 65537, 4 * sizeof(Elf64_Dyn) + 65537, true);
}

static void row_dyn_table_4096(struct img *m)
{
    dyn_standard(m, 4096, IMG_STRSZ, 4096 * sizeof(Elf64_Dyn) + IMG_STRSZ, true);
}

static void row_dyn_table_4097(struct img *m)
{
    dyn_standard(m, 4097, IMG_STRSZ, 4097 * sizeof(Elf64_Dyn) + IMG_STRSZ, true);
}

/* STRTAB points past its load. The string a wrapped-around offset would land
 * on is a valid "libc.so.6", so only the bounds check can refuse it. */
static void row_dyn_strtab_outside(struct img *m)
{
    Elf64_Dyn e[] = {dyn(DT_STRTAB, IMG_DATA_VADDR + 0x10000), dyn(DT_STRSZ, IMG_STRSZ),
                     dyn(DT_NEEDED, 0), dyn(DT_NULL, 0)};
    struct dyn_plan p = {e, 4, 4, 4 * sizeof(Elf64_Dyn) + IMG_STRSZ, true};
    img_dynamic(m, &p);
    memcpy(m->bytes + IMG_DYN_OFF + 0x10000, "libc.so.6", IMG_STRSZ);
}

struct img_row {
    const char *name;
    void (*build)(struct img *);
    bool accept;
};

static int img_run_rows(const char *group, const struct img_row *rows, size_t count)
{
    int failures = 0;
    TEST_CASE(group) {
        int bad = 0;
        for (size_t i = 0; i < count; i++) {
            struct img m;
            img_begin(&m, img_buffer, sizeof(img_buffer));
            rows[i].build(&m);
            enum platform_supervised_image_result want = rows[i].accept
                ? PLATFORM_SUPERVISED_IMAGE_OK : PLATFORM_SUPERVISED_IMAGE_REFUSED;
            enum platform_supervised_image_result got = img_capture(&m);
            if (got != want) {
                printf("\n  row %s: got %d want %d", rows[i].name, (int)got, (int)want);
                bad++;
            }
        }
        ASSERT_EQ(bad, 0);
    } TEST_END
    return failures;
}

static int img_header_rows(void)
{
    static const struct img_row rows[] = {
        {"base image", row_base, true},
        {"ET_DYN accepted", row_type_dyn, true},
        {"ET_REL refused", row_type_rel, false},
        {"note at end of file", row_note_at_end, true},
        {"note past end of file", row_note_past_end, false},
        {"128 headers", row_phnum_128, true},
        {"129 headers", row_phnum_129, false},
        {"GNU_STACK rw", row_stack_rw, true},
        {"GNU_STACK x", row_stack_x, false},
        {"static + bad PT_INTERP", row_static_bad_interp, false},
        {"static + empty PT_DYNAMIC", row_static_dynamic_empty, false},
        {"static + odd PT_DYNAMIC", row_static_dynamic_odd, false},
        {"entry last byte", row_entry_last_byte, true},
        {"entry one past load", row_entry_past_end, false},
    };
    return img_run_rows("supervised_process: ELF header and segment boundaries",
                        rows, sizeof(rows) / sizeof(rows[0]));
}

static int img_load_rows(void)
{
    static const struct img_row rows[] = {
        {"R loads adjacent", row_r_adjacent, true},
        {"R loads adjacent reversed", row_r_adjacent_reversed, true},
        {"R loads overlap", row_r_overlap, false},
        {"RX loads share a page", row_rx_same_page, true},
        {"odd-end RX/RW share a page", row_odd_page_overlap, false},
        {"RX then RW on next page", row_page_adjacent, true},
        {"RW then RX on previous page", row_page_adjacent_reversed, true},
        {"RX and RW a page apart", row_page_gap, true},
        {"filesz above memsz", row_bad_filesz, false},
        {"write and exec", row_bad_write_exec, false},
        {"memsz beyond address space", row_bad_memsz_huge, false},
        {"vaddr beyond address space", row_bad_vaddr_huge, false},
        {"align 2 mismatch", row_bad_align_two, false},
        {"align 3 not a power of two", row_bad_align_three, false},
        {"page align mismatch", row_bad_align_page, false},
        {"largest memsz", row_memsz_max, true},
        {"highest vaddr, entry at vaddr", row_vaddr_max, true},
    };
    return img_run_rows("supervised_process: ELF load geometry boundaries",
                        rows, sizeof(rows) / sizeof(rows[0]));
}

static int img_dynamic_rows(void)
{
    static const struct img_row rows[] = {
        {"tight dynamic maps", row_dyn_tight, true},
        {"NEEDED without interpreter", row_dyn_no_interp, false},
        {"DF_BIND_NOW", row_dyn_flags_bind_now, true},
        {"DF_TEXTREL", row_dyn_flags_textrel, false},
        {"two NEEDED", row_dyn_two_needed, false},
        {"interpreter without NEEDED", row_dyn_no_needed_interp, false},
        {"NEEDED first and third", row_dyn_needed_first, false},
        {"static-pie, no NEEDED", row_dyn_static_pie, true},
        {"second PT_DYNAMIC", row_dyn_second_dynamic, false},
        {"STRSZ 65536", row_dyn_strsz_max, true},
        {"STRSZ 65537", row_dyn_strsz_over, false},
        {"4096 dynamic entries", row_dyn_table_4096, true},
        {"4097 dynamic entries", row_dyn_table_4097, false},
        {"STRTAB outside its load", row_dyn_strtab_outside, false},
    };
    return img_run_rows("supervised_process: ELF dynamic section boundaries",
                        rows, sizeof(rows) / sizeof(rows[0]));
}

/* ---- capture entry-point cases ---- */
static int img_capture_limits(void)
{
    int failures = 0;
    TEST_CASE("supervised_process: image size limit, short header, digest and fd failure") {
        struct img m;
        uint8_t digest[32] = {0};
        int fd = -1;
        img_begin(&m, img_buffer, sizeof(img_buffer));
        ASSERT_EQ(img_capture(&m), PLATFORM_SUPERVISED_IMAGE_OK);
        /* A valid image cut below one ELF header is refused, not parsed. */
        ASSERT_EQ(platform_supervised_image_capture(img_buffer, sizeof(Elf64_Ehdr) - 1, digest, &fd),
                  PLATFORM_SUPERVISED_IMAGE_REFUSED);
        /* A digest that does not match is an I/O-class failure with no fd. */
        ASSERT_EQ(platform_supervised_image_capture(img_buffer, sizeof(img_buffer), digest, &fd),
                  PLATFORM_SUPERVISED_IMAGE_IO_ERROR);
        ASSERT_EQ(fd, -1);
    } TEST_END
    return failures;
}

static int img_capture_descriptor_limit(void)
{
    int failures = 0;
    TEST_CASE("supervised_process: image capture reports a descriptor-limit failure") {
        struct img m;
        struct rlimit old, low;
        img_begin(&m, img_buffer, sizeof(img_buffer));
        ASSERT_EQ(getrlimit(RLIMIT_NOFILE, &old), 0);
        low = old;
        low.rlim_cur = 0;
        ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &low), 0);
        enum platform_supervised_image_result result = img_capture(&m);
        ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &old), 0);
        ASSERT_EQ(result, PLATFORM_SUPERVISED_IMAGE_IO_ERROR);
    } TEST_END
    return failures;
}

static int img_capture_max_size(void)
{
    int failures = 0;
    uint8_t *big = calloc(1, PLATFORM_SUPERVISED_IMAGE_MAX);
    TEST_CASE("supervised_process: image of exactly the size limit is accepted") {
        struct img m;
        ASSERT(big != NULL);
        img_begin(&m, big, PLATFORM_SUPERVISED_IMAGE_MAX);
        ASSERT_EQ(img_capture(&m), PLATFORM_SUPERVISED_IMAGE_OK);
    } TEST_END
    free(big);
    return failures;
}

int supervised_image_policy_tests(void);
int supervised_image_policy_tests(void)
{
    int failures = 0;
    failures += img_header_rows();
    failures += img_load_rows();
    failures += img_dynamic_rows();
    failures += img_capture_limits();
    failures += img_capture_descriptor_limit();
    failures += img_capture_max_size();
    return failures;
}
#else
int supervised_image_policy_tests(void);
int supervised_image_policy_tests(void)
{
    return 0;
}
#endif
