/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * run_parity_oracle_selftest - proves the run_parity_oracle driver against a
 * stub compiler: argument routing, exit-status propagation, compile failure,
 * the two-pass profile mode, and removal of every temporary binary on normal
 * exit, SIGINT and SIGTERM.
 *
 * usage: run_parity_oracle_selftest <driver> <scratch-dir>
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>

#define BUF 4096

static const char k_stub_cc[] =
    "#!/bin/sh\n"
    "[ -n \"$STUB_CC_FAIL\" ] && exit \"$STUB_CC_FAIL\"\n"
    "while [ $# -gt 0 ]; do [ \"$1\" = -o ] && out=$2; shift; done\n"
    "printf '#!/bin/sh\\necho started $$\\necho \"args: $*\"\\n%s\\n' "
    "\"$STUB_BIN_TAIL\" > \"$out\"\n"
    "chmod +x \"$out\"\n";

static int g_failures;

static void pot_check(int ok, const char *what)
{
    if (ok) return;
    fprintf(stderr, "run_parity_oracle_selftest: FAIL %s\n", what);
    g_failures++;
}

struct pot_run { pid_t pid; int out; };

static struct pot_run pot_start(const char *driver, const char *mode, const char *n)
{
    int p[2];
    struct pot_run r = {-1, -1};
    if (pipe(p) != 0) return r;
    pid_t pid = fork();
    if (pid == 0) {
        dup2(p[1], 1);
        close(p[0]);
        close(p[1]);
        execl(driver, driver, mode, n, (char *)nullptr);
        _exit(127);
    }
    close(p[1]);
    r.pid = pid;
    r.out = p[0];
    return r;
}

static size_t pot_slurp(int fd, char *buf, size_t cap)
{
    size_t len = 0;
    ssize_t k;
    while (len + 1 < cap && (k = read(fd, buf + len, cap - len - 1)) > 0) len += (size_t)k;
    buf[len] = '\0';
    close(fd);
    return len;
}

static int pot_files_left(const char *dir)
{
    int count = 0;
    DIR *d = opendir(dir);
    struct dirent *e;
    while (d && (e = readdir(d)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) count++;
    if (d) closedir(d);
    return count;
}

static void pot_configure(const char *tmp, const char *fail, const char *tail)
{
    setenv("TMPDIR", tmp, 1);
    setenv("STUB_CC_FAIL", fail, 1);
    setenv("STUB_BIN_TAIL", tail, 1);
}

static int pot_finish(struct pot_run r, char *out, size_t cap)
{
    int st = 0;
    pot_slurp(r.out, out, cap);
    waitpid(r.pid, &st, 0);
    return st;
}

static void pot_case_exit(const char *drv, const char *tmp, const char *name, const char *fail,
                      const char *tail, const char *mode, int want, const char *marker)
{
    char out[BUF];
    pot_configure(tmp, fail, tail);
    int st = pot_finish(pot_start(drv, mode, ""), out, sizeof out);
    pot_check(WIFEXITED(st) && WEXITSTATUS(st) == want, name);
    pot_check(marker == nullptr || strstr(out, marker) != nullptr, name);
    pot_check(pot_files_left(tmp) == 0, name);
}

static void pot_case_signal(const char *drv, const char *tmp, int sig, int times, const char *name)
{
    char line[BUF];
    pot_configure(tmp, "", "exec sleep 30");
    struct pot_run r = pot_start(drv, "check", "");
    ssize_t k = read(r.out, line, sizeof line - 1);
    line[k > 0 ? k : 0] = '\0';
    long child = strncmp(line, "started ", 8) == 0 ? strtol(line + 8, nullptr, 10) : 0;
    pot_check(child > 0, name);
    for (int i = 0; i < times; i++) kill(r.pid, sig);
    int st = pot_finish(r, line, sizeof line);
    pot_check(WIFSIGNALED(st) && WTERMSIG(st) == sig, name);
    pot_check(pot_files_left(tmp) == 0, name);
    pot_check(child > 0 && kill((pid_t)child, 0) != 0 && errno == ESRCH, name);
}

static int pot_write_stub(const char *dir)
{
    char path[BUF + 32];
    if (snprintf(path, sizeof path, "%s/cc", dir) >= (int)sizeof path) return -1;
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(k_stub_cc, f);
    fclose(f);
    return chmod(path, 0755);
}

static int pot_remove_tree(const char *root, const char *bin, const char *tmp)
{
    char stub[BUF + 32];
    snprintf(stub, sizeof stub, "%s/cc", bin);
    return unlink(stub) | rmdir(bin) | rmdir(tmp) | rmdir(root);
}


/* Runs the oracle binary itself (record/check take a directory; the driver
 * wrapper always uses the committed corpus). stderr goes to errpath when it
 * is non-null. Returns its exit status, or -1. */
static int pot_run_real(const char *drv, const char *mode, const char *dir,
                        const char *errpath)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (errpath) {
            int fd = open(errpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0 || dup2(fd, 2) < 0) _exit(126);
            close(fd);
        }
        execl(drv, drv, mode, dir, (char *)nullptr);
        _exit(127);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}

static bool pot_file_has(const char *path, const char *needle)
{
    char buf[65536];
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t got = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[got] = '\0';
    return strstr(buf, needle) != nullptr;
}

/* Byte offset where record two starts in groth16_decode_corpus.bin: the
 * magic, a u32 count, then record one (fam u8, verdict u8, ilen u16, input,
 * llen u16, label). Returns -1 when the file is too short to hold record one.
 * The magic literal mirrors DECODE_MAGIC in groth16_parity_oracle.c. */
static long pot_record_two_offset(const char *path)
{
    const size_t magic = sizeof("G16PARITY-DECODE-01\n") - 1;
    unsigned char hdr[512];
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t got = fread(hdr, 1, sizeof hdr, f);
    fclose(f);
    if (got < magic + 4 + 4) return -1;
    uint16_t ilen = 0, llen = 0;
    size_t off = magic + 4;
    memcpy(&ilen, hdr + off + 2, sizeof ilen);
    off += 4 + ilen;
    if (off + sizeof llen > got) return -1;
    memcpy(&llen, hdr + off, sizeof llen);
    off += sizeof llen + llen;
    return off > got ? -1 : (long)off;
}

static void pot_remove_fixture(const char *dir)
{
    static const char *const names[] = {
        "groth16_parity_golden.bin", "groth16_decode_corpus.bin",
        "groth16_pairing_values.bin"};
    char path[BUF * 2 + 32];
    for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
        snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        unlink(path);
    }
    rmdir(dir);
}

/* Records the frozen files with the oracle, cuts one of them with cut(), and
 * requires check to exit 1 AND report "truncated record". Any other failure
 * (crash, bad magic, other mismatch) fails the selftest. */
static void pot_case_truncated(const char *oracle, const char *root,
                               const char *name, const char *file, bool decode)
{
    char dir[BUF * 2], path[BUF * 2 + 32], errp[BUF * 2 + 32], msg[128];
    snprintf(dir, sizeof dir, "%s/trunc-%s", root, name);
    snprintf(errp, sizeof errp, "%s/stderr.txt", dir);
    pot_check(mkdir(dir, 0755) == 0, "truncated fixture dir");
    pot_check(pot_run_real(oracle, "record", dir, nullptr) == 0, "truncated fixture record");
    snprintf(path, sizeof path, "%s/%s", dir, file);
    long cut = -1;
    if (decode) {
        cut = pot_record_two_offset(path);
    } else {
        struct stat sb;
        if (stat(path, &sb) == 0 && sb.st_size > 1) cut = (long)sb.st_size - 1;
    }
    pot_check(cut > 0 && truncate(path, cut) == 0, "truncated fixture cut");
    snprintf(msg, sizeof msg, "truncated %s corpus exits 1", name);
    pot_check(pot_run_real(oracle, "check", dir, errp) == 1, msg);
    snprintf(msg, sizeof msg, "truncated %s corpus reports truncated record", name);
    pot_check(pot_file_has(errp, "truncated record"), msg);
    unlink(errp);
    pot_remove_fixture(dir);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <driver> <scratch-dir> <oracle>\n", argv[0]);
        return 2;
    }
    char root[BUF], bin[BUF + 16], tmp[BUF + 16], path[BUF * 2 + 32];
    if (snprintf(root, sizeof root, "%s/parity-selftest.XXXXXX", argv[2]) >= (int)sizeof root) return 2;
    if (!mkdtemp(root)) { perror("mkdtemp"); return 2; }
    snprintf(bin, sizeof bin, "%s/bin", root);
    snprintf(tmp, sizeof tmp, "%s/tmp", root);
    if (mkdir(bin, 0755) || mkdir(tmp, 0755) || pot_write_stub(bin)) return 2;
    snprintf(path, sizeof path, "%s:%s", bin, getenv("PATH") ? getenv("PATH") : "/usr/bin");
    setenv("PATH", path, 1);

    pot_case_exit(argv[1], tmp, "check passes arguments", "", "exit 0", "check", 0, "args: check ");
    pot_case_exit(argv[1], tmp, "bench routes to comb", "", "exit 0", "bench", 0, "args: comb 30");
    pot_case_exit(argv[1], tmp, "pairing routes", "", "exit 0", "pairing", 0, "args: pairing 30");
    pot_case_exit(argv[1], tmp, "child status propagates", "", "exit 3", "check", 3, nullptr);
    pot_case_exit(argv[1], tmp, "compile status propagates", "5", "exit 0", "check", 5, nullptr);
    pot_case_exit(argv[1], tmp, "profile runs two passes", "", "exit 0", "profile", 0,
              "profile pass 2/2");
    pot_case_exit(argv[1], tmp, "child killed by signal", "", "kill -9 $$", "check", 137, nullptr);
    pot_case_signal(argv[1], tmp, SIGTERM, 1, "SIGTERM cleans up");
    pot_case_signal(argv[1], tmp, SIGINT, 1, "SIGINT cleans up");
    pot_case_signal(argv[1], tmp, SIGHUP, 1, "SIGHUP cleans up");
    pot_case_signal(argv[1], tmp, SIGTERM, 2, "repeated SIGTERM cleans up");
    pot_case_signal(argv[1], tmp, SIGINT, 2, "repeated SIGINT cleans up");
    pot_case_truncated(argv[3], root, "decode", "groth16_decode_corpus.bin", true);
    pot_case_truncated(argv[3], root, "pairing", "groth16_pairing_values.bin", false);

    if (g_failures == 0 && pot_remove_tree(root, bin, tmp) != 0) return 2;
    puts(g_failures ? "run_parity_oracle_selftest: FAILED"
                    : "run_parity_oracle_selftest: ALL CASES OK");
    return g_failures != 0;
}
