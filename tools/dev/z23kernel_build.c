/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Build the freestanding RV64 kernel and refuse a bad image. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include "z23kernel_build.h"

#include <stdio.h>
#include <string.h>

static int zk_fail(const char *msg)
{
    fprintf(stderr, "z23kernel: %s\n", msg);
    return 1;
}

#if !defined(_WIN32)
#include "build_epoch_lock_wait.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct zk_job {
    char source[PATH_MAX];
    char output[PATH_MAX];
    char bindir[PATH_MAX];
    const char *cc;
    const char *ld;
    const char *objcopy;
    const char *readelf;
    const char *nm;
    uint64_t start, probe, resume, bss, end, bottom, top;
    int lock_fd;
};

struct zk_sec {
    char name[64];
    char type[32];
    uint64_t addr;
    uint64_t size;
};

static const char *zk_pick(const char *given, const char *env, const char *fallback)
{
    const char *value;
    if (given != NULL && given[0] != '\0')
        return given;
    value = getenv(env);
    if (value != NULL && value[0] != '\0')
        return value;
    return fallback;
}

static int zk_abs(const char *path, char *out, size_t cap)
{
    char resolved[PATH_MAX];
    if (path == NULL || realpath(path, resolved) == NULL)
        return -1;
    if (strlen(resolved) + 1 > cap)
        return -1;
    memcpy(out, resolved, strlen(resolved) + 1);
    return 0;
}

static int zk_reap(pid_t pid)
{
    int status = 0;
    pid_t got = -1;
    while (got != pid) {
        got = waitpid(pid, &status, 0);
        if (got >= 0)
            continue;
        if (errno != EINTR)
            return 127;
    }
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    if (!WIFEXITED(status))
        return 127;
    return WEXITSTATUS(status);
}

static int zk_exec(const char *cwd, char *const argv[], const char *stdout_path)
{
    pid_t pid = fork();
    int fd;
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (chdir(cwd) != 0)
            _exit(127);
        if (stdout_path != NULL) {
            fd = open(stdout_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0)
                _exit(127);
            close(fd);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    return zk_reap(pid);
}

static int zk_split(char *line, char **field, int cap)
{
    int n = 0;
    char *cursor = line;
    while (*cursor != '\0' && n < cap) {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' ||
               *cursor == '\r')
            cursor++;
        if (*cursor == '\0')
            break;
        field[n++] = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' &&
               *cursor != '\n' && *cursor != '\r')
            cursor++;
        if (*cursor != '\0')
            *cursor++ = '\0';
    }
    return n;
}

static int zk_has_line(const char *path, const char *prefix)
{
    FILE *file = fopen(path, "r");
    char line[512];
    int found = 0;
    if (file == NULL)
        return 0;
    while (fgets(line, (int)sizeof line, file) != NULL) {
        if (strncmp(line, prefix, strlen(prefix)) == 0) {
            found = 1;
            break;
        }
    }
    fclose(file);
    return found;
}

static int zk_dynamic_sections(const char *path)
{
    FILE *file = fopen(path, "r");
    char line[1024];
    int count = 0;
    if (file == NULL)
        return -1;
    while (fgets(line, (int)sizeof line, file) != NULL) {
        char *field[24];
        int n;
        int i;
        const char *start = line;
        while (*start == ' ' || *start == '\t')
            start++;
        if (*start != '[')
            continue;
        n = zk_split(line, field, 24);
        for (i = 0; i < n; i++)
            if (strcmp(field[i], "DYNAMIC") == 0)
                count++;
    }
    fclose(file);
    return count;
}

static int zk_dynamic_programs(const char *path)
{
    FILE *file = fopen(path, "r");
    char line[1024];
    int count = 0;
    if (file == NULL)
        return -1;
    while (fgets(line, (int)sizeof line, file) != NULL) {
        char *field[8];
        int n = zk_split(line, field, 8);
        if (n > 0 && (strcmp(field[0], "DYNAMIC") == 0 ||
                      strcmp(field[0], "INTERP") == 0))
            count++;
    }
    fclose(file);
    return count;
}

static int zk_hex(const char *text, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value;
    if (text == NULL || text[0] == '\0')
        return -1;
    value = strtoull(text, &end, 16);
    if (end == text || *end != '\0')
        return -1;
    *out = (uint64_t)value;
    return 0;
}

static int zk_symbol(const char *path, const char *name, uint64_t *out)
{
    FILE *file = fopen(path, "r");
    char line[512];
    if (file == NULL)
        return -1;
    while (fgets(line, (int)sizeof line, file) != NULL) {
        char *field[6];
        int n = zk_split(line, field, 6);
        if (n >= 3 && strcmp(field[0], name) == 0) {
            int rc = zk_hex(field[2], out);
            fclose(file);
            return rc;
        }
    }
    fclose(file);
    return -1;
}

static int zk_flagged(char **field, int n, int index)
{
    return index + 6 < n && strchr(field[index + 6], 'A') != NULL &&
           field[index][0] == '.';
}

static int zk_sections(const char *path, struct zk_sec *sec, int cap, int *count)
{
    FILE *file = fopen(path, "r");
    char line[1024];
    *count = 0;
    if (file == NULL)
        return -1;
    while (fgets(line, (int)sizeof line, file) != NULL) {
        char *field[24];
        int n = zk_split(line, field, 24);
        int i;
        for (i = 0; i < n; i++) {
            uint64_t addr = 0;
            uint64_t size = 0;
            if (!zk_flagged(field, n, i))
                continue;
            if (zk_hex(field[i + 2], &addr) != 0 || zk_hex(field[i + 4], &size) != 0)
                continue;
            if (*count >= cap) {
                fclose(file);
                return -1;
            }
            snprintf(sec[*count].name, sizeof sec[*count].name, "%s", field[i]);
            snprintf(sec[*count].type, sizeof sec[*count].type, "%s", field[i + 1]);
            sec[*count].addr = addr;
            sec[*count].size = size;
            (*count)++;
            break;
        }
    }
    fclose(file);
    return 0;
}

static int zk_load(const char *path, unsigned char *buf, size_t cap, size_t *out)
{
    FILE *file = fopen(path, "rb");
    size_t n;
    if (file == NULL)
        return -1;
    n = fread(buf, 1, cap, file);
    if (ferror(file) || fread(buf, 1, 1, file) == 1) {
        fclose(file);
        return -1;
    }
    fclose(file);
    *out = n;
    return 0;
}

static int zk_compare_section(struct zk_job *job, const struct zk_sec *sec)
{
    char spec[PATH_MAX];
    char dumped[PATH_MAX];
    char copy[PATH_MAX];
    char image[PATH_MAX];
    unsigned char section[65536];
    unsigned char flat[65536];
    size_t section_n = 0;
    size_t flat_n = 0;
    uint64_t skip;
    char *argv[6];
    FILE *bin;
    if (sec->size > sizeof section || sec->addr < job->start)
        return zk_fail("allocated section does not fit the image");
    skip = sec->addr - job->start;
    if (snprintf(dumped, sizeof dumped, "%s/zk-section", job->output) >=
            (int)sizeof dumped ||
        snprintf(copy, sizeof copy, "%s/zk-elf-copy", job->output) >=
            (int)sizeof copy ||
        snprintf(spec, sizeof spec, "%s=%s", sec->name, dumped) >= (int)sizeof spec)
        return zk_fail("section path is too long");
    argv[0] = (char *)job->objcopy;
    argv[1] = "--dump-section";
    argv[2] = spec;
    argv[3] = "kernel.elf";
    argv[4] = copy;
    argv[5] = NULL;
    if (zk_exec(job->output, argv, NULL) != 0)
        return zk_fail("section dump failed");
    if (zk_load(dumped, section, sizeof section, &section_n) != 0 ||
        section_n != sec->size)
        return zk_fail("dumped section size is wrong");
    if (snprintf(image, sizeof image, "%s/kernel.bin", job->output) >=
        (int)sizeof image)
        return zk_fail("kernel.bin path is too long");
    bin = fopen(image, "rb");
    if (bin == NULL)
        return zk_fail("kernel.bin is missing");
    if (fseeko(bin, (off_t)skip, SEEK_SET) != 0 ||
        fread(flat, 1, (size_t)sec->size, bin) != sec->size) {
        fclose(bin);
        return zk_fail("flat image does not contain the section");
    }
    fclose(bin);
    flat_n = (size_t)sec->size;
    unlink(dumped);
    unlink(copy);
    if (flat_n != section_n || memcmp(section, flat, section_n) != 0)
        return zk_fail("flat image does not match an allocated section");
    return 0;
}

static int zk_one_section(struct zk_job *job, const struct zk_sec *sec)
{
    if (strcmp(sec->name, ".eh_frame_hdr") == 0)
        return 0;
    if (sec->addr < job->start || sec->addr + sec->size < sec->addr ||
        sec->addr + sec->size > job->end)
        return zk_fail("allocated section is outside the image");
    if (strcmp(sec->type, "NOBITS") == 0)
        return 0;
    if (strcmp(sec->type, "PROGBITS") == 0)
        return zk_compare_section(job, sec);
    fprintf(stderr, "z23kernel: unsupported allocated section %s\n", sec->name);
    return 1;
}

static int zk_need(const struct zk_sec *sec, int count, const char *name,
                   const char *type)
{
    int i;
    for (i = 0; i < count; i++)
        if (strcmp(sec[i].name, name) == 0 && strcmp(sec[i].type, type) == 0)
            return 0;
    return zk_fail("required section is missing");
}

static int zk_sha256(struct zk_job *job, char hex[65])
{
    char path[PATH_MAX];
    char line[256];
    char *field[4];
    FILE *file;
    char *argv[3];
    int n;
    if (snprintf(path, sizeof path, "%s/zk-sha256", job->output) >= (int)sizeof path)
        return -1;
    argv[0] = "sha256sum";
    argv[1] = "kernel.bin";
    argv[2] = NULL;
    if (zk_exec(job->output, argv, path) != 0)
        return -1;
    file = fopen(path, "r");
    if (file == NULL || fgets(line, (int)sizeof line, file) == NULL) {
        if (file != NULL)
            fclose(file);
        return -1;
    }
    fclose(file);
    unlink(path);
    n = zk_split(line, field, 4);
    if (n < 1 || strlen(field[0]) != 64)
        return -1;
    memcpy(hex, field[0], 65);
    return 0;
}

static int zk_copy_file(const char *from, const char *to)
{
    FILE *in = fopen(from, "rb");
    FILE *out = fopen(to, "wb");
    unsigned char buf[8192];
    size_t n;
    if (in == NULL || out == NULL) {
        if (in != NULL)
            fclose(in);
        if (out != NULL)
            fclose(out);
        return -1;
    }
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in);
            fclose(out);
            return -1;
        }
    }
    if (ferror(in) || fclose(out) != 0) {
        fclose(in);
        return -1;
    }
    fclose(in);
    return 0;
}

static int zk_publish(struct zk_job *job, const char *hash)
{
    char tmp_bin[PATH_MAX];
    char tmp_id[PATH_MAX];
    char dst_bin[PATH_MAX];
    char dst_id[PATH_MAX];
    char src_bin[PATH_MAX];
    char src_id[PATH_MAX];
    FILE *identity;
    int pid = (int)getpid();
    if (snprintf(tmp_bin, sizeof tmp_bin, "%s/z23kernel.bin.tmp.%d", job->bindir,
                 pid) >= (int)sizeof tmp_bin ||
        snprintf(tmp_id, sizeof tmp_id, "%s/z23kernel.identity.tmp.%d", job->bindir,
                 pid) >= (int)sizeof tmp_id ||
        snprintf(dst_bin, sizeof dst_bin, "%s/z23kernel.bin", job->bindir) >=
            (int)sizeof dst_bin ||
        snprintf(dst_id, sizeof dst_id, "%s/z23kernel.identity", job->bindir) >=
            (int)sizeof dst_id ||
        snprintf(src_bin, sizeof src_bin, "%s/kernel.bin", job->output) >=
            (int)sizeof src_bin ||
        snprintf(src_id, sizeof src_id, "%s/kernel.identity", job->output) >=
            (int)sizeof src_id)
        return zk_fail("publish path is too long");
    identity = fopen(src_id, "w");
    if (identity == NULL)
        return zk_fail("kernel.identity could not be written");
    if (fprintf(identity, "%s %" PRIx64 " %" PRIx64 " %" PRIx64 "\n", hash,
                job->probe - job->start, job->resume - job->start,
                job->end - job->start) < 0 ||
        fclose(identity) != 0)
        return zk_fail("kernel.identity could not be written");
    if (zk_copy_file(src_bin, tmp_bin) != 0 || zk_copy_file(src_id, tmp_id) != 0)
        return zk_fail("kernel image could not be copied");
    if (rename(tmp_bin, dst_bin) != 0 || rename(tmp_id, dst_id) != 0)
        return zk_fail("kernel image could not be published");
    return 0;
}

static int zk_capture(struct zk_job *job, char *sections, size_t sections_cap,
                      char *programs, size_t programs_cap, char *symbols,
                      size_t symbols_cap)
{
    char review[PATH_MAX];
    char *review_argv[] = {(char *)job->readelf, "-h", "-l", "-SW", "-s", "-d",
                           "kernel.elf", NULL};
    char *section_argv[] = {(char *)job->readelf, "-SW", "kernel.elf", NULL};
    char *program_argv[] = {(char *)job->readelf, "-lW", "kernel.elf", NULL};
    char *nm_argv[] = {(char *)job->nm, "-P", "--defined-only", "kernel.elf", NULL};
    if (snprintf(review, sizeof review, "%s/elf-review.log", job->output) >=
            (int)sizeof review ||
        snprintf(sections, sections_cap, "%s/sections.raw", job->output) >=
            (int)sections_cap ||
        snprintf(programs, programs_cap, "%s/programs.raw", job->output) >=
            (int)programs_cap ||
        snprintf(symbols, symbols_cap, "%s/symbols.log", job->output) >=
            (int)symbols_cap)
        return zk_fail("inspection path is too long");
    if (zk_exec(job->output, review_argv, review) != 0)
        return zk_fail("readelf review failed");
    if (zk_exec(job->output, section_argv, sections) != 0 ||
        zk_exec(job->output, program_argv, programs) != 0)
        return zk_fail("readelf headers failed");
    if (zk_exec(job->output, nm_argv, symbols) != 0)
        return zk_fail("nm failed");
    return 0;
}

static int zk_reject_dynamic(const char *sections, const char *programs)
{
    if (!zk_has_line(sections, "Section Headers:") ||
        !zk_has_line(programs, "Program Headers:"))
        return zk_fail("ELF inspection output is unrecognized");
    if (zk_dynamic_sections(sections) != 0)
        return zk_fail("kernel has a dynamic section");
    if (zk_dynamic_programs(programs) != 0)
        return zk_fail("kernel has a dynamic program header");
    return 0;
}

static int zk_load_symbols(struct zk_job *job, const char *symbols)
{
    if (zk_symbol(symbols, "_start", &job->start) != 0 ||
        zk_symbol(symbols, "illegal_probe", &job->probe) != 0 ||
        zk_symbol(symbols, "illegal_resume", &job->resume) != 0 ||
        zk_symbol(symbols, "__bss_start", &job->bss) != 0 ||
        zk_symbol(symbols, "_end", &job->end) != 0 ||
        zk_symbol(symbols, "stack_bottom", &job->bottom) != 0 ||
        zk_symbol(symbols, "stack_top", &job->top) != 0)
        return zk_fail("required symbol is missing");
    return 0;
}

static int zk_layout(const struct zk_job *job)
{
    if (job->start != 0x80200000ULL || job->resume - job->probe != 4)
        return zk_fail("kernel entry layout is wrong");
    if ((job->top % 16) != 0 || job->top - job->bottom != 16384)
        return zk_fail("kernel stack layout is wrong");
    if (job->bss < 0x80200000ULL || job->end > 0x80300000ULL)
        return zk_fail("kernel image is outside the bounded window");
    return 0;
}

static int zk_check_sections(struct zk_job *job, const char *sections)
{
    struct zk_sec sec[16];
    int count = 0;
    int i;
    if (zk_sections(sections, sec, 16, &count) != 0)
        return zk_fail("section table could not be read");
    if (zk_need(sec, count, ".text", "PROGBITS") != 0 ||
        zk_need(sec, count, ".bss", "NOBITS") != 0 ||
        zk_need(sec, count, ".rodata", "PROGBITS") != 0)
        return 1;
    for (i = 0; i < count; i++)
        if (zk_one_section(job, &sec[i]) != 0)
            return 1;
    return 0;
}

static int zk_finish(struct zk_job *job)
{
    char image[PATH_MAX];
    struct stat st;
    char hash[65];
    if (snprintf(image, sizeof image, "%s/kernel.bin", job->output) >=
        (int)sizeof image)
        return zk_fail("kernel.bin path is too long");
    if (stat(image, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size >= 65536)
        return zk_fail("kernel.bin is missing or too large");
    if (zk_sha256(job, hash) != 0)
        return zk_fail("kernel.bin hash failed");
    return zk_publish(job, hash);
}

static int zk_inspect(struct zk_job *job)
{
    char sections[PATH_MAX];
    char programs[PATH_MAX];
    char symbols[PATH_MAX];
    if (zk_capture(job, sections, sizeof sections, programs, sizeof programs,
                   symbols, sizeof symbols) != 0)
        return 1;
    if (zk_reject_dynamic(sections, programs) != 0)
        return 1;
    if (zk_load_symbols(job, symbols) != 0)
        return 1;
    if (zk_layout(job) != 0)
        return 1;
    if (zk_check_sections(job, sections) != 0)
        return 1;
    return zk_finish(job);
}

static int zk_cc_main(struct zk_job *job)
{
    char main_c[PATH_MAX];
    char *argv[] = {(char *)job->cc,
                    "--target=riscv64-unknown-elf",
                    "-std=c23",
                    "-march=rv64ima_zicsr",
                    "-mabi=lp64",
                    "-mcmodel=medany",
                    "-msmall-data-limit=0",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-fno-stack-protector",
                    "-fno-pic",
                    "-mno-relax",
                    "-fno-unwind-tables",
                    "-fno-asynchronous-unwind-tables",
                    "-O1",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pedantic",
                    "-fstack-usage",
                    "-c",
                    main_c,
                    "-o",
                    "main.o",
                    NULL};
    if (snprintf(main_c, sizeof main_c, "%s/main.c", job->source) >=
        (int)sizeof main_c)
        return zk_fail("source path is too long");
    if (zk_exec(job->output, argv, NULL) != 0)
        return zk_fail("main.c compile failed");
    return 0;
}

static int zk_cc_entry(struct zk_job *job)
{
    char entry[PATH_MAX];
    char *argv[] = {(char *)job->cc,
                    "--target=riscv64-unknown-elf",
                    "-march=rv64ima_zicsr",
                    "-mabi=lp64",
                    "-mcmodel=medany",
                    "-mno-relax",
                    "-c",
                    entry,
                    "-o",
                    "entry.o",
                    NULL};
    if (snprintf(entry, sizeof entry, "%s/entry.S", job->source) >= (int)sizeof entry)
        return zk_fail("source path is too long");
    if (zk_exec(job->output, argv, NULL) != 0)
        return zk_fail("entry.S compile failed");
    return 0;
}

static int zk_link(struct zk_job *job)
{
    char *argv[] = {(char *)job->ld,
                    "-m",
                    "elf64lriscv",
                    "-static",
                    "--build-id=none",
                    "--no-relax",
                    "-e",
                    "_start",
                    "--image-base",
                    "0x80000000",
                    "--Ttext=0x80200000",
                    "--section-start=.rodata=0x80201000",
                    "-o",
                    "kernel.elf",
                    "entry.o",
                    "main.o",
                    NULL};
    if (zk_exec(job->output, argv, NULL) != 0)
        return zk_fail("link failed");
    return 0;
}

static int zk_compile(struct zk_job *job)
{
    if (zk_cc_main(job) != 0)
        return 1;
    if (zk_cc_entry(job) != 0)
        return 1;
    return zk_link(job);
}
#endif

int zcl_z23kernel_build(const char *source_dir, const char *output_dir,
                        const char *bin_dir, const char *cc, const char *ld,
                        const char *objcopy, const char *readelf, const char *nm)
{
#if defined(_WIN32)
    (void)source_dir;
    (void)output_dir;
    (void)bin_dir;
    (void)cc;
    (void)ld;
    (void)objcopy;
    (void)readelf;
    (void)nm;
    return zk_fail("unsupported platform");
#else
    struct zk_job job;
    char lock[PATH_MAX];
    char *obj_argv[8];
    memset(&job, 0, sizeof job);
    job.lock_fd = -1;
    job.cc = zk_pick(cc, "Z23KERNEL_CC", "clang");
    job.ld = zk_pick(ld, "Z23KERNEL_LD", "ld.lld");
    job.objcopy = zk_pick(objcopy, "Z23KERNEL_OBJCOPY", "llvm-objcopy");
    job.readelf = zk_pick(readelf, "Z23KERNEL_READELF", "readelf");
    job.nm = zk_pick(nm, "Z23KERNEL_NM", "nm");
    if (output_dir == NULL ||
        (mkdir(output_dir, 0755) != 0 && errno != EEXIST))
        return zk_fail("output directory is unavailable");
    if (zk_abs(source_dir, job.source, sizeof job.source) != 0 ||
        zk_abs(output_dir, job.output, sizeof job.output) != 0 ||
        zk_abs(bin_dir, job.bindir, sizeof job.bindir) != 0)
        return zk_fail("source, output, or bin directory does not resolve");
    if (snprintf(lock, sizeof lock, "%s/build.lock", job.output) >= (int)sizeof lock)
        return zk_fail("lock path is too long");
    job.lock_fd = open(lock, O_RDWR | O_CREAT, 0644);
    if (job.lock_fd < 0 ||
        zcl_build_epoch_flock_bounded("z23kernel", job.lock_fd, lock,
                                     "kernel-output", STDERR_FILENO) != 0) {
        if (job.lock_fd >= 0)
            close(job.lock_fd);
        return zk_fail("kernel output lock was not acquired");
    }
    if (zk_compile(&job) != 0) {
        close(job.lock_fd);
        return 1;
    }
    obj_argv[0] = (char *)job.objcopy;
    obj_argv[1] = "-O";
    obj_argv[2] = "binary";
    obj_argv[3] = "--remove-section=.eh_frame_hdr";
    obj_argv[4] = "kernel.elf";
    obj_argv[5] = "kernel.bin";
    obj_argv[6] = NULL;
    if (zk_exec(job.output, obj_argv, NULL) != 0) {
        close(job.lock_fd);
        return zk_fail("objcopy failed");
    }
    if (zk_inspect(&job) != 0) {
        close(job.lock_fd);
        return 1;
    }
    close(job.lock_fd);
    return 0;
#endif
}
