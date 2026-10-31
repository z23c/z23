/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The shipped z23-dev maps GTK and WebKit only for an explicit
 * GUI launch. Headless boot keeps the tiny-guest pins.
 */
#include "test/test_core.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define GUI_BIN "build/bin/z23-dev"
#define GUI_SO "build/bin/libz23walletgui.so"
#define GUI_CAPTURE (4u * 1024u * 1024u)
/* The C runtime a dynamic image must name: glibc/musl on ELF hosts, libSystem
 * on macOS. Selected per platform, never accepted interchangeably. */
#ifdef __APPLE__
#define GUI_LIBC_FRAGMENT "libSystem"
#else
#define GUI_LIBC_FRAGMENT "libc.so"
#endif

static uint16_t rd16(const unsigned char *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof v);
    return v;
}

static uint32_t rd32(const unsigned char *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof v);
    return v;
}

static uint64_t rd64(const unsigned char *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof v);
    return v;
}

static int host_is_le(void)
{
    uint16_t one = 1;
    return *(unsigned char *)&one == 1;
}

static int elf_read(FILE *f, unsigned char *dst, size_t n, uint64_t off)
{
    if (off > (uint64_t)LONG_MAX || fseek(f, (long)off, SEEK_SET) != 0)
        return -1;
    return fread(dst, 1, n, f) == n ? 0 : -1;
}

static int elf_header(FILE *f, uint64_t *phoff, uint16_t *phentsize, uint16_t *phnum)
{
    unsigned char eh[64];
    if (!host_is_le() || elf_read(f, eh, sizeof eh, 0) != 0)
        return -1;
    if (memcmp(eh, "\177ELF", 4) != 0 || eh[4] != 2 || eh[5] != 1)
        return -1;
    *phoff = rd64(eh + 32);
    *phentsize = rd16(eh + 54);
    *phnum = rd16(eh + 56);
    if (*phnum == 0 || *phnum > 128 || *phentsize < 56)
        return -1;
    return 0;
}

static int elf_phdr_at(FILE *f, uint64_t phoff, uint16_t entsize, uint16_t index,
                       unsigned char *out)
{
    unsigned char raw[64];
    uint64_t off;
    if (entsize > sizeof raw)
        return -1;
    off = phoff + (uint64_t)entsize * index;
    if (elf_read(f, raw, entsize, off) != 0)
        return -1;
    memcpy(out, raw, 56);
    return 0;
}

static int elf_dynamic(FILE *f, uint64_t phoff, uint16_t phnum, uint16_t entsize,
                       uint64_t *dyn_off, uint64_t *dyn_sz)
{
    uint16_t i;
    *dyn_off = 0;
    *dyn_sz = 0;
    for (i = 0; i < phnum; i++) {
        unsigned char ph[56];
        if (elf_phdr_at(f, phoff, entsize, i, ph) != 0)
            return -1;
        if (rd32(ph) != 2)
            continue;
        *dyn_off = rd64(ph + 8);
        *dyn_sz = rd64(ph + 32);
    }
    if (*dyn_sz < 16 || *dyn_sz > (1u << 20))
        return -1;
    return 0;
}

static int elf_load_span(FILE *f, uint64_t phoff, uint16_t phnum, uint16_t entsize,
                         uint64_t vaddr, uint64_t *off)
{
    uint16_t i;
    for (i = 0; i < phnum; i++) {
        unsigned char ph[56];
        uint64_t poff, pvaddr, filesz;
        if (elf_phdr_at(f, phoff, entsize, i, ph) != 0)
            return -1;
        if (rd32(ph) != 1)
            continue;
        poff = rd64(ph + 8);
        pvaddr = rd64(ph + 16);
        filesz = rd64(ph + 32);
        if (vaddr >= pvaddr && vaddr - pvaddr < filesz) {
            *off = poff + (vaddr - pvaddr);
            return 0;
        }
    }
    return -1;
}

static int elf_strtab_off(FILE *f, const unsigned char *dyn, size_t dyn_sz,
                          uint64_t phoff, uint16_t phnum, uint16_t entsize,
                          uint64_t *str_off)
{
    size_t i;
    uint64_t str_vaddr = 0;
    for (i = 0; i + 16 <= dyn_sz; i += 16) {
        int64_t tag = 0;
        memcpy(&tag, dyn + i, sizeof tag);
        if (tag == 0)
            break;
        if (tag == 5)
            memcpy(&str_vaddr, dyn + i + 8, sizeof str_vaddr);
    }
    if (str_vaddr == 0)
        return -1;
    return elf_load_span(f, phoff, phnum, entsize, str_vaddr, str_off);
}

static int elf_read_name(FILE *f, uint64_t str_base, uint64_t val, char *out, size_t cap)
{
    char raw[256];
    size_t n;
    size_t len;
    uint64_t at;
    if (val > (1u << 20) || str_base > UINT64_MAX - val)
        return -1;
    at = str_base + val;
    if (at > (uint64_t)LONG_MAX || fseek(f, (long)at, SEEK_SET) != 0)
        return -1;
    n = fread(raw, 1, sizeof raw - 1, f);
    if (n == 0)
        return -1;
    raw[n] = '\0';
    /* The string table sits mid-file, so a short soname still fills this
     * buffer. A name is missing only when those bytes contain no NUL. */
    if (memchr(raw, '\0', n) == NULL)
        return -1;
    len = strlen(raw);
    if (len + 1 > cap)
        return -1;
    memcpy(out, raw, len + 1);
    return 0;
}

static int elf_collect_needed(FILE *f, const unsigned char *dyn, size_t dyn_sz,
                              uint64_t str_off, char *names, size_t cap)
{
    size_t i;
    size_t used = 0;
    names[0] = '\0';
    for (i = 0; i + 16 <= dyn_sz; i += 16) {
        int64_t tag = 0;
        uint64_t val = 0;
        char soname[256];
        size_t len;
        memcpy(&tag, dyn + i, sizeof tag);
        if (tag == 0)
            break;
        if (tag != 1)
            continue;
        memcpy(&val, dyn + i + 8, sizeof val);
        if (elf_read_name(f, str_off, val, soname, sizeof soname) != 0)
            return -1;
        len = strlen(soname);
        if (used + len + 2 > cap)
            return -1;
        memcpy(names + used, soname, len);
        used += len;
        names[used++] = '\n';
        names[used] = '\0';
    }
    return used > 0 ? 0 : -1;
}

/* A Mach-O image has no DT_NEEDED; its dependencies are the dylib load
 * commands. Constants are spelled out so the parser needs no Apple header
 * and an ELF host simply never reaches it. Thin little-endian 64-bit only,
 * which is what a native build links. Returns 1 when `f` is such an image
 * (names filled, or -1 on a malformed one), 0 when it is not Mach-O. */
/* Read the load-command block of such an image into *cmds (the caller frees
 * it): 1 when read, 0 when `f` is not Mach-O, -1 when malformed. */
static int macho_read_cmds(FILE *f, unsigned char **cmds, uint32_t *ncmds,
                           uint32_t *sizeofcmds)
{
    unsigned char hdr[32];

    *cmds = NULL;
    *ncmds = 0;
    *sizeofcmds = 0;
    if (!host_is_le() || elf_read(f, hdr, sizeof hdr, 0) != 0 ||
        rd32(hdr) != 0xfeedfacfu)
        return 0;
    *ncmds = rd32(hdr + 16);
    *sizeofcmds = rd32(hdr + 20);
    if (*sizeofcmds == 0 || *sizeofcmds > (16u << 20))
        return -1;
    *cmds = malloc(*sizeofcmds);
    if (*cmds == NULL || elf_read(f, *cmds, *sizeofcmds, sizeof hdr) != 0)
        return -1;
    return 1;
}

/* LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB
 * (0x20) and LC_LOAD_UPWARD_DYLIB. */
static bool macho_is_dylib_cmd(uint32_t cmd)
{
    return cmd == 0xcu || cmd == 0x20u || cmd == 0x80000018u ||
           cmd == 0x8000001fu ||
           cmd == 0x80000023u;
}

/* Append the dylib name of the `size`-byte load command at `lc` to names;
 * -1 when the command is malformed or names is full. */
static int macho_append_dylib(const unsigned char *lc, uint32_t size,
                              char *names, size_t cap, size_t *used)
{
    uint32_t name_off;
    size_t len;

    if (size < 24)
        return -1;
    name_off = rd32(lc + 8);
    if (name_off < 24 || name_off >= size)
        return -1;
    len = strnlen((const char *)lc + name_off, size - name_off);
    if (len == size - name_off || *used + len + 2 > cap)
        return -1;
    memcpy(names + *used, lc + name_off, len);
    *used += len;
    names[(*used)++] = '\n';
    names[*used] = '\0';
    return 0;
}

static int macho_needed(FILE *f, char *names, size_t cap)
{
    unsigned char *cmds;
    uint32_t ncmds, sizeofcmds, off = 0, i;
    size_t used = 0;
    int rc = macho_read_cmds(f, &cmds, &ncmds, &sizeofcmds);

    if (rc <= 0) {
        free(cmds);
        return rc;
    }
    rc = -1;
    for (i = 0; i < ncmds; i++) {
        uint32_t cmd, size;
        if (off > sizeofcmds || sizeofcmds - off < 8)
            goto out;
        cmd = rd32(cmds + off);
        size = rd32(cmds + off + 4);
        if (size < 8 || size > sizeofcmds - off)
            goto out;
        if (macho_is_dylib_cmd(cmd) &&
            macho_append_dylib(cmds + off, size, names, cap, &used) != 0)
            goto out;
        off += size;
    }
    rc = (used > 0 && off == sizeofcmds) ? 1 : -1;
out:
    free(cmds);
    return rc;
}

static int elf_needed(const char *path, char *names, size_t cap)
{
    FILE *f;
    unsigned char *dyn = NULL;
    uint64_t phoff = 0, dyn_off = 0, dyn_sz = 0, str_off = 0;
    uint16_t phentsize = 0, phnum = 0;
    int rc;

    names[0] = '\0';
    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "wallet gui load: cannot open %s\n", path);
        return -1;
    }
    rc = macho_needed(f, names, cap);
    if (rc != 0) {
        if (rc < 0)
            fprintf(stderr, "wallet gui load: dylib load commands of %s are unreadable\n", path);
        fclose(f);
        return rc < 0 ? -1 : 0;
    }
    if (elf_header(f, &phoff, &phentsize, &phnum) != 0 ||
        elf_dynamic(f, phoff, phnum, phentsize, &dyn_off, &dyn_sz) != 0) {
        fprintf(stderr, "wallet gui load: %s is not a readable ELF64 image\n", path);
        fclose(f);
        return -1;
    }
    dyn = malloc((size_t)dyn_sz);
    if (dyn == NULL || elf_read(f, dyn, (size_t)dyn_sz, dyn_off) != 0 ||
        elf_strtab_off(f, dyn, (size_t)dyn_sz, phoff, phnum, phentsize, &str_off) != 0) {
        fprintf(stderr, "wallet gui load: cannot read DT_STRTAB of %s\n", path);
        free(dyn);
        fclose(f);
        return -1;
    }
    rc = elf_collect_needed(f, dyn, (size_t)dyn_sz, str_off, names, cap);
    if (rc != 0)
        fprintf(stderr, "wallet gui load: DT_NEEDED parse failed for %s\n", path);
    free(dyn);
    fclose(f);
    return rc;
}

static int names_contain(const char *names, const char *fragment)
{
    return strstr(names, fragment) != NULL;
}

static int closed_libs_absent(const char *names)
{
    static const char *const banned[] = {
        "libgtk", "libgdk-3", "libwebkit", "libjavascriptcore"
    };
    size_t i;
    if (!names_contain(names, GUI_LIBC_FRAGMENT)) {
        fprintf(stderr, "wallet gui load: DT_NEEDED did not name libc\n%s", names);
        return 1;
    }
    for (i = 0; i < sizeof banned / sizeof banned[0]; i++) {
        if (names_contain(names, banned[i])) {
            fprintf(stderr, "wallet gui load: headless z23-dev needs %s\n%s",
                    banned[i], names);
            return 1;
        }
    }
    return 0;
}

static int gui_so_links_toolkit(const char *names)
{
    if (!names_contain(names, "libgtk") || !names_contain(names, "libwebkit")) {
        fprintf(stderr, "wallet gui load: GUI library is missing GTK or WebKit\n%s",
                names);
        return 1;
    }
    return 0;
}

/* 1 when the companion lists GTK and WebKit, 0 when this host built the
 * closed stub or did not build the companion, -1 when the image is unreadable. */
static int so_toolkit_state(char *names, size_t cap)
{
    if (access(GUI_SO, R_OK) != 0)
        return 0;
    if (elf_needed(GUI_SO, names, cap) != 0)
        return -1;
    if (!names_contain(names, "libgtk") || !names_contain(names, "libwebkit"))
        return 0;
    return 1;
}

struct gui_env_slot {
    const char *key;
    char saved[512];
    int had;
};

static int gui_env_save(struct gui_env_slot *slot)
{
    const char *v = getenv(slot->key);
    slot->had = 0;
    slot->saved[0] = '\0';
    if (v == NULL)
        return 0;
    if (strlen(v) >= sizeof slot->saved)
        return -1;
    memcpy(slot->saved, v, strlen(v) + 1);
    slot->had = 1;
    return 0;
}

static void gui_env_restore(const struct gui_env_slot *slot)
{
    if (slot->had)
        (void)setenv(slot->key, slot->saved, 1);
    else
        unsetenv(slot->key);
}

/* Wayland opens display "wayland-0" when WAYLAND_DISPLAY is unset. Forcing
 * the X11 backend with DISPLAY unset makes gtk_init_check fail before the
 * wallet GUI touches a datadir. */
static int run_captured(const char *const argv[], char *buf, size_t cap,
                        struct zcl_spawn_binary_observation *observed)
{
    struct gui_env_slot display = { .key = "DISPLAY" };
    struct gui_env_slot wayland = { .key = "WAYLAND_DISPLAY" };
    struct gui_env_slot backend = { .key = "GDK_BACKEND" };

    if (gui_env_save(&display) != 0 || gui_env_save(&wayland) != 0 ||
        gui_env_save(&backend) != 0)
        return -1;
    if (setenv("LD_DEBUG", "files", 1) != 0 ||
        setenv("GDK_BACKEND", "x11", 1) != 0) {
        unsetenv("LD_DEBUG");
        gui_env_restore(&display);
        gui_env_restore(&wayland);
        gui_env_restore(&backend);
        return -1;
    }
    unsetenv("DISPLAY");
    unsetenv("WAYLAND_DISPLAY");
    (void)zcl_spawn_capture_binary_merged(argv, buf, cap, 30000, observed);
    unsetenv("LD_DEBUG");
    gui_env_restore(&display);
    gui_env_restore(&wayland);
    gui_env_restore(&backend);
    if (observed->output_len < cap)
        buf[observed->output_len] = '\0';
    else
        buf[cap - 1] = '\0';
    return 0;
}

static void put32(unsigned char *p, uint32_t v)
{
    memcpy(p, &v, sizeof v);
}

/* Synthetic thin 64-bit Mach-O: one dylib command of each kind the reader
 * must see (load, lazy, weak, re-export, upward) between two commands it
 * must skip. Runs on every little-endian host; it needs no Apple binary. */
static int test_macho_dylib_commands(const char *dir)
{
    static const uint32_t kinds[] = {0xcu, 0x20u, 0x80000018u, 0x8000001fu,
                                     0x80000023u};
    static const char *const libs[] = {"/usr/lib/libload.dylib",
                                       "/usr/lib/liblazy.dylib",
                                       "/usr/lib/libweak.dylib",
                                       "/usr/lib/libreexport.dylib",
                                       "/usr/lib/libupward.dylib"};
    unsigned char img[1024];
    char path[600], names[1024];
    int failures = 0;
    TEST("Mach-O reader names load, lazy, weak, re-export and upward dylibs") {
        size_t off = 32;
        uint32_t ncmds = 0;
        memset(img, 0, sizeof img);
        put32(img, 0xfeedfacfu);
        put32(img + off, 0x1bu);              /* LC_UUID: not a dylib */
        put32(img + off + 4, 24);
        off += 24;
        ncmds++;
        for (size_t i = 0; i < 5; i++) {
            size_t len = strlen(libs[i]) + 1;
            uint32_t size = (uint32_t)((24 + len + 7) & ~(size_t)7);
            put32(img + off, kinds[i]);
            put32(img + off + 4, size);
            put32(img + off + 8, 24);
            memcpy(img + off + 24, libs[i], len);
            off += size;
            ncmds++;
        }
        put32(img + off, 0x2au);              /* LC_SOURCE_VERSION: skipped */
        put32(img + off + 4, 16);
        off += 16;
        ncmds++;
        put32(img + 16, ncmds);
        put32(img + 20, (uint32_t)(off - 32));
        ASSERT(snprintf(path, sizeof path, "%s/synthetic.macho", dir) > 0);
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        ASSERT(fwrite(img, 1, off, f) == off);
        ASSERT(fclose(f) == 0);
        if (host_is_le()) {
            ASSERT(elf_needed(path, names, sizeof names) == 0);
            for (size_t i = 0; i < 5; i++)
                ASSERT(names_contain(names, libs[i]));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_needed_headless(void)
{
    char names[8192];
    int failures = 0;
    TEST("shipped z23-dev does not need GTK or WebKit") {
        ASSERT(elf_needed(GUI_BIN, names, sizeof names) == 0);
        ASSERT(closed_libs_absent(names) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_needed_gui_so(void)
{
    char names[8192];
    int failures = 0;
    TEST("wallet GUI library links GTK and WebKit when that library is built") {
        int state = so_toolkit_state(names, sizeof names);
        ASSERT(state >= 0);
        if (state == 1)
            ASSERT(gui_so_links_toolkit(names) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_gui_launch_toolkit(char *buf, const char *const argv[])
{
    struct zcl_spawn_binary_observation observed = {0};
    int failures = 0;

    TEST("explicit -gui loads the real wallet GUI") {
        ASSERT(run_captured(argv, buf, GUI_CAPTURE, &observed) == 0);
        ASSERT(!observed.overflow);
        ASSERT(!observed.timed_out);
        ASSERT(observed.exit_code == 1);
        ASSERT(strstr(buf, "Cannot open display") != NULL);
        ASSERT(strstr(buf, "libwebkit") != NULL);
        ASSERT(strstr(buf, "GUI not available") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int gui_closed_text(const char *buf)
{
    if (strstr(buf, "GUI not available") != NULL)
        return 1;
    if (strstr(buf, "is not beside the executable") != NULL)
        return 1;
    if (strstr(buf, "cannot load") != NULL)
        return 1;
    return 0;
}

static int test_gui_launch_closed(char *buf, const char *const argv[])
{
    struct zcl_spawn_binary_observation observed = {0};
    int failures = 0;

    TEST("explicit -gui stays closed without the toolkit library") {
        ASSERT(run_captured(argv, buf, GUI_CAPTURE, &observed) == 0);
        ASSERT(!observed.overflow);
        ASSERT(!observed.timed_out);
        ASSERT(observed.exit_code == 1);
        ASSERT(gui_closed_text(buf) == 1);
        ASSERT(strstr(buf, "libgtk") == NULL);
        ASSERT(strstr(buf, "libwebkit") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_gui_launch(const char *dir)
{
    char names[8192];
    char *buf;
    char datadir_arg[600];
    const char *argv[4];
    int state;
    int failures;

    snprintf(datadir_arg, sizeof datadir_arg, "-datadir=%s", dir);
    argv[0] = GUI_BIN;
    argv[1] = datadir_arg;
    argv[2] = "-gui";
    argv[3] = NULL;
    buf = malloc(GUI_CAPTURE);
    if (buf == NULL)
        return 1;
    state = so_toolkit_state(names, sizeof names);
    if (state < 0) {
        free(buf);
        return 1;
    }
    failures = state == 1 ? test_gui_launch_toolkit(buf, argv)
                          : test_gui_launch_closed(buf, argv);
    free(buf);
    return failures;
}

static int test_headless_boot(const char *dir)
{
    char *buf;
    char datadir_arg[600];
    char input[160];
    struct zcl_spawn_binary_observation observed = {0};
    const char *argv[8];
    int failures = 0;

    snprintf(datadir_arg, sizeof datadir_arg, "-datadir=%s", dir);
    snprintf(input, sizeof input,
             "--input={\"kernel\":\"tests/fixtures/rvmachine/tiny.bin\",\"max_instr\":100000}");
    argv[0] = GUI_BIN;
    argv[1] = datadir_arg;
    argv[2] = "dev";
    argv[3] = "app";
    argv[4] = "machine";
    argv[5] = "boot";
    argv[6] = input;
    argv[7] = NULL;
    buf = malloc(GUI_CAPTURE);
    if (buf == NULL)
        return 1;
    TEST("headless tiny boot does not map GTK or WebKit") {
        ASSERT(run_captured(argv, buf, GUI_CAPTURE, &observed) == 0);
        ASSERT(!observed.overflow);
        ASSERT(observed.exit_code == 0);
        ASSERT(strstr(buf, "\"retired\":279") != NULL);
        ASSERT(strstr(buf, "\"fw_calls\":62") != NULL);
        ASSERT(strstr(buf, "\"device_work\":0") != NULL);
        ASSERT(strstr(buf, "tiny: hello from S-mode\\n") != NULL);
        ASSERT(strstr(buf, "libgtk") == NULL);
        ASSERT(strstr(buf, "libwebkit") == NULL);
        ASSERT(strstr(buf, "libjavascriptcore") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int test_wallet_gui_load(void);
int test_wallet_gui_load(void)
{
#if defined(_WIN32)
    printf("test_wallet_gui_load: skipped on Windows\n");
    return 0;
#else
    char dir[512];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "wallet_gui", "load");
    failures = test_macho_dylib_commands(dir) + test_needed_headless() +
               test_needed_gui_so() +
               test_gui_launch(dir) + test_headless_boot(dir);
    test_rm_rf(dir);
    return failures;
#endif
}
