/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check-zcc-cache Apple suite (Darwin only): the selected backend
 * executable, the PATH-resolved clang, an external assembler and a -B
 * selection must each key the cache by bytes, never by mtime or PATH text;
 * a mid-compile mutation must not publish; a missing fact must be UNKEY.
 * Also the bootstrap signature check, which only exists on Apple.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc_text.h"
#include "lintc.h"
#include "gate_zcc_cache_priv.h"

static const char ap_race_msg[] = "compiled; inputs changed during compilation";

/* A fixture file with an explicit mode (csr_write leaves the mode open). */
static int ap_file(const char *name, const char *text, mode_t mode)
{
    return zc_put(name, text) || chmod(zcw("%s", name), mode) != 0;
}

/* Run argv capturing trimmed stdout. */
static void ap_out(const char *const *argv, char *out, size_t cap)
{
    struct zc_cmd c = { .argv = argv, .out = out, .cap = cap };
    zc_run(&c);
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
}

/* Compile through zcc; env gets ZCC_DIR/ZCC_LOG first, extra entries after. */
static void ap_zcc(const char *cache, const char *log, const char *const *extra,
                   const char *const *args, const char *msg)
{
    const char *env[8] = { zc_zd(cache), zcf("ZCC_LOG=%s", log) };
    int ne = 2;
    for (int i = 0; extra && extra[i] && ne < 7; i++)
        env[ne++] = extra[i];
    const char *av[16] = { zc.zcc };
    int na = 1;
    for (int i = 0; args[i] && na < 15; i++)
        av[na++] = args[i];
    if (zc_x(av, env, NULL) != 0)
        zc_fail(msg);
}

/* ---- selected backend executable ---- */

static const char ap_driver[] =
    "#!/bin/sh\nfor arg in \"$@\"; do\n    case \"$arg\" in\n"
    "        -print-prog-name=clang) printf '%s\\n' \"$ZCC_APPLE_BACKEND\"; exit 0 ;;\n"
    "    esac\ndone\nexec \"$ZCC_APPLE_BACKEND\" \"$@\"\n";

static void ap_backend(const char *cache, const char *log, const char *backend,
                       const char *const *more, const char *msg)
{
    const char *extra[6] = { zcf("ZCC_APPLE_BACKEND=%s", backend) };
    for (int i = 0; more && more[i] && i < 4; i++)
        extra[i + 1] = more[i];
    const char *const args[] = { zcw("apple-backend-driver"), "-std=c23", "-c",
        zcw("apple-backend.c"), "-o", zcw("apple-backend.o"), NULL };
    ap_zcc(cache, log, extra, args, msg);
}

static int ap_backend_same_size(const char *log, const char *cache)
{
    const char *be = zcw("apple-backend");
    if (zc_copy(be, zcw("apple-backend-time"), 1) ||
        zc_sed_first(zcw("apple-backend-time"), zcw("apple-backend-new"),
                     "body changed", "body altered"))
        return 1;
    struct stat sb, sa;
    if (stat(be, &sb))
        return 1;
    if (zc_copy(zcw("apple-backend-new"), be, 0) ||
        zc_touch_ref(zcw("apple-backend-time"), be))
        return 1;
    zc_want(stat(be, &sa) == 0 && sa.st_size == sb.st_size,
            "Apple backend same-size fixture changed length");
    ap_backend(cache, log, be, NULL, "Apple selected backend compile failed");
    zc_disp_in(log, "MISS", "same-size backend edit with restored mtime was served from cache");
    ap_backend(cache, log, be, NULL, "Apple selected backend compile failed");
    zc_disp_in(log, "HIT", "same-size backend did not return to HIT");
    return 0;
}

static int ap_backend_main(void)
{
    const char *cache = zcw("apple-backend-cache"), *log = zcw("apple-backend.log");
    const char *be = zcw("apple-backend");
    if (ap_file("apple-backend-driver", ap_driver, 0700) ||
        ap_file("apple-backend", "#!/bin/sh\nexec /usr/bin/cc \"$@\"\n", 0700) ||
        zc_put("apple-backend.c", "int zcc_apple_backend(void) { return 23; }\n"))
        return 1;
    ap_backend(cache, log, be, NULL, "Apple selected backend compile failed");
    zc_disp_in(log, "MISS", "Apple backend cold compile was not a MISS");
    ap_backend(cache, log, be, NULL, "Apple selected backend compile failed");
    zc_disp_in(log, "HIT", "Apple backend warm compile was not a HIT");
    FILE *f = fopen(be, "a");
    if (!f)
        return 1;
    fputs("# backend body changed; version reply stays constant\n", f);
    fclose(f);
    ap_backend(cache, log, be, NULL, "Apple selected backend compile failed");
    zc_disp_in(log, "MISS", "changed Apple backend bytes were served from cache");
    ap_backend(cache, log, be, NULL, "Apple selected backend compile failed");
    zc_disp_in(log, "HIT", "unchanged Apple backend did not return to HIT");
    return ap_backend_same_size(log, cache);
}

/* ---- backend mutated while the real compiler runs ---- */

static const char ap_race[] =
    "#!/bin/sh\ncase \" $* \" in\n    *' -E '*) exec /usr/bin/cc \"$@\" ;;\nesac\n"
    "printf 'compile\\n' >> \"$APPLE_RACE_COMPILES\"\n"
    "if [ ! -e \"$APPLE_RACE_MARK\" ]; then\n    : > \"$APPLE_RACE_MARK\"\n"
    "    printf '# changed during physical compile\\n' >> \"$0\"\nfi\n"
    "exec /usr/bin/cc \"$@\"\n";

static void ap_race_compile(void)
{
    const char *more[] = { zcf("APPLE_RACE_MARK=%s", zcw("apple-backend-race.once")),
        zcf("APPLE_RACE_COMPILES=%s", zcw("apple-backend-race.compiles")), NULL };
    ap_backend(zcw("apple-backend-race-cache"), zcw("apple-backend-race.log"),
               zcw("apple-backend-race"), more, "Apple backend race compile failed");
}

/* One fixture executable mutated mid-compile: the cache must key it by bytes. */
struct ap_race {
    const char *name;    /* fixture executable, relative to the work directory */
    const char *stem;    /* prefix of the original, changed and log files */
    const char *counter; /* file that counts the physical compiles */
    const char *noun;    /* "backend" or "assembler", for the messages */
    const char *counted; /* what the counter records */
    const char *stale;   /* the script's message for a published stale key */
    const char *body;    /* fixture text */
    void (*compile)(void);
};

static int ap_race_run(const struct ap_race *r)
{
    const char *log = zcw("%s.log", r->stem), *be = zcw("%s", r->name);
    if (ap_file(r->name, r->body, 0700) ||
        zc_copy(be, zcw("%s-original", r->stem), 1) || zc_put(r->counter, ""))
        return 1;
    r->compile();
    zc_want(lct_file_has(log, ap_race_msg), zcf("mid-compile %s mutation was not detected", r->noun));
    if (zc_copy(be, zcw("%s-changed", r->stem), 1) ||
        zc_copy(zcw("%s-original", r->stem), be, 0))
        return 1;
    r->compile();
    zc_disp_in(log, "MISS", r->stale);
    if (zc_copy(zcw("%s-changed", r->stem), be, 0))
        return 1;
    r->compile();
    zc_disp_in(log, "MISS", zcf("mid-compile %s mutation seeded a stale cache hit", r->noun));
    r->compile();
    zc_disp_in(log, "HIT", zcf("stable %s after the race did not return to HIT", r->noun));
    zc_want(zc_lines(zcw("%s", r->counter)) == 3,
            zcf("Apple %s race did not execute exactly three %s", r->noun, r->counted));
    return 0;
}

/* ---- clang resolved through PATH ---- */

static const char ap_path_driver[] =
    "#!/bin/sh\ncase \"$1\" in\n    -print-prog-name=clang)\n"
    "        printf 'query\\n' >> \"$APPLE_PATH_QUERIES\"\n"
    "        command -v clang\n        exit $? ;;\nesac\n"
    "selected=\"$(command -v clang)\" || exit 1\nexec \"$selected\" \"$@\"\n";

static void ap_path_compile(void)
{
    const char *path = zcf("PATH=%s:%s:%s", zcw("apple-path-first"),
                           zcw("apple-path-second"), env_or("PATH", "/usr/bin:/bin"));
    const char *extra[] = { path, "COMPILER_PATH=",
        zcf("APPLE_PATH_QUERIES=%s", zcw("apple-path-queries")), NULL };
    const char *const args[] = { zcw("apple-path-driver"), "-std=c23", "-c",
        zcw("apple-backend.c"), "-o", zcw("apple-backend.o"), NULL };
    ap_zcc(zcw("apple-path-cache"), zcw("apple-path.log"), extra, args,
           "Apple PATH backend compile failed");
}

static int ap_backend_path(void)
{
    const char *log = zcw("apple-path.log"), *q = zcw("apple-path-queries");
    static const char clang[] = "#!/bin/sh\nexec /usr/bin/cc \"$@\"\n";
    if (ap_file("apple-path-first/clang", clang, 0600) ||
        ap_file("apple-path-second/clang", clang, 0700) ||
        ap_file("apple-path-driver", ap_path_driver, 0700) || zc_put("apple-path-queries", ""))
        return 1;
    ap_path_compile();
    zc_disp_in(log, "MISS", "Apple PATH backend cold compile was not a MISS");
    ap_path_compile();
    zc_disp_in(log, "HIT", "Apple PATH backend warm compile was not a HIT");
    zc_want(zc_lines(q) == 1, "Apple default backend memo launched a warm driver query");
    if (chmod(zcw("apple-path-first/clang"), 0700))
        return 1;
    ap_path_compile();
    zc_disp_in(log, "MISS", "newly executable Apple PATH backend was served from cache");
    ap_path_compile();
    zc_disp_in(log, "HIT", "unchanged Apple PATH backend did not return to HIT");
    zc_want(zc_lines(q) == 2, "Apple default backend memo did not requery exactly after chmod");
    return 0;
}

static int ap_backend_unknown(void)
{
    if (ap_file("apple-unknown-backend",
                "#!/bin/sh\ncase \" $* \" in\n    *' -print-prog-name=clang '*) exit 0 ;;\n"
                "esac\nexec /usr/bin/cc \"$@\"\n", 0700))
        return 1;
    const char *const args[] = { zcw("apple-unknown-backend"), "-std=c23", "-c",
        zcw("apple-backend.c"), "-o", zcw("apple-backend.o"), NULL };
    ap_zcc(zcw("apple-backend-cache"), zcw("apple-backend.log"), NULL, args,
           "Apple missing-backend-fact compile failed");
    zc_disp_in(zcw("apple-backend.log"), "UNKEY",
               "missing Apple backend fact did not fail cache admission");
    return 0;
}

/* ---- external assembler (-fno-integrated-as) ---- */

static char ap_as[ZC_PATH];

/* cc -B<b1> -B<b2> -print-prog-name=as, trimmed. */
static void ap_prog_as(const char *b1, const char *b2, char *out, size_t cap)
{
    const char *av[6] = { "cc" };
    int n = 1;
    if (b1)
        av[n++] = zcf("-B%s", b1);
    if (b2)
        av[n++] = zcf("-B%s", b2);
    av[n++] = "-print-prog-name=as";
    av[n] = NULL;
    ap_out(av, out, cap);
}

static void ap_as_compile(const char *cache, const char *log, const char *b1,
                          const char *b2, const char *const *extra, const char *msg)
{
    const char *args[10] = { "cc", "-std=c23", "-fno-integrated-as" };
    int n = 3;
    args[n++] = zcf("-B%s", b1);
    if (b2)
        args[n++] = zcf("-B%s", b2);
    args[n++] = "-c";
    args[n++] = zcw("apple-as.c");
    args[n++] = "-o";
    args[n++] = zcw("apple-as.o");
    args[n] = NULL;
    ap_zcc(cache, log, extra, args, msg);
}

static int ap_as_basic(void)
{
    const char *cache = zcw("apple-as-cache"), *log = zcw("apple-as.log");
    const char *dir = zcw("apple-as"), *m = "Apple external assembler compile failed";
    if (ap_file("apple-as/as", zcf("#!/bin/sh\n# first body\nexec \"%s\" \"$@\"\n", ap_as),
                0700) ||
        zc_put("apple-as.c", "int zcc_apple_as(void) { return 23; }\n"))
        return 1;
    struct zc_cmd c = { .argv = ZC_ARGV("cc", "-###", "-std=c23", "-fno-integrated-as",
        zcf("-B%s", dir), "-c", zcw("apple-as.c"), "-o", zcw("apple-as.o")),
        .outf = zcw("apple-as-driver"), .merge = 1 };
    zc_want(zc_run(&c) == 0, "Apple assembler driver query failed");
    zc_want(lct_file_has(zcw("apple-as-driver"), zcw("apple-as/as")),
            "Apple driver did not select the fixture assembler");
    ap_as_compile(cache, log, dir, NULL, NULL, m);
    zc_disp_in(log, "MISS", "Apple assembler cold compile was not a MISS");
    ap_as_compile(cache, log, dir, NULL, NULL, m);
    zc_disp_in(log, "HIT", "Apple assembler warm compile was not a HIT");
    FILE *f = fopen(zcw("apple-as/as"), "a");
    if (!f)
        return 1;
    fputs("# changed body; version output is unchanged\n", f);
    fclose(f);
    ap_as_compile(cache, log, dir, NULL, NULL, m);
    zc_disp_in(log, "MISS", "changed Apple assembler bytes were served from cache");
    return 0;
}

static const char ap_as_race[] =
    "#!/bin/sh\nprintf 'assemble\\n' >> \"$APPLE_AS_RACE_CALLS\"\n"
    "if [ ! -e \"$APPLE_AS_RACE_MARK\" ]; then\n    : > \"$APPLE_AS_RACE_MARK\"\n"
    "    printf '# changed during physical assembly\\n' >> \"$0\"\nfi\n"
    "exec \"$APPLE_AS_REAL\" \"$@\"\n";

static void ap_as_race_compile(void)
{
    const char *extra[] = { zcf("APPLE_AS_REAL=%s", ap_as),
        zcf("APPLE_AS_RACE_MARK=%s", zcw("apple-as-race.once")),
        zcf("APPLE_AS_RACE_CALLS=%s", zcw("apple-as-race.calls")), NULL };
    ap_as_compile(zcw("apple-as-race-cache"), zcw("apple-as-race.log"),
                  zcw("apple-as-race"), NULL, extra, "Apple assembler race compile failed");
}

static const struct ap_race ap_backend_race_spec = {
    .name = "apple-backend-race", .stem = "apple-backend-race",
    .counter = "apple-backend-race.compiles", .noun = "backend",
    .counted = "physical compiles", .body = ap_race, .compile = ap_race_compile,
    .stale = "the old backend key was published despite a mid-compile mutation",
};

static const struct ap_race ap_as_race_spec = {
    .name = "apple-as-race/as", .stem = "apple-as-race",
    .counter = "apple-as-race.calls", .noun = "assembler",
    .counted = "assemblies", .body = ap_as_race, .compile = ap_as_race_compile,
    .stale = "the old assembler key was published despite mutation",
};

/* -B is a prefix selector: zcc queries the driver every time. */
static int ap_as_select(void)
{
    const char *log = zcw("apple-selection.log"), *cache = zcw("apple-selection-cache");
    const char *first = zcw("apple-first"), *second = zcw("apple-second");
    const char *m = "Apple selection-change compile failed";
    char sel[ZC_PATH];
    if (ap_file("apple-first/as", zcf("#!/bin/sh\nexec \"%s\" \"$@\"\n", ap_as), 0600) ||
        ap_file("apple-second/as", zcf("#!/bin/sh\nexec \"%s\" \"$@\"\n", ap_as), 0700))
        return 1;
    ap_prog_as(first, second, sel, sizeof sel);
    zc_want(strcmp(sel, zcw("apple-second/as")) == 0,
            "Apple selector fixture did not initially choose the later tool");
    ap_as_compile(cache, log, first, second, NULL, m);
    zc_disp_in(log, "MISS", "Apple later-assembler cold compile was not a MISS");
    ap_as_compile(cache, log, first, second, NULL, m);
    zc_disp_in(log, "HIT", "Apple later-assembler warm compile was not a HIT");
    if (chmod(zcw("apple-first/as"), 0700))
        return 1;
    ap_prog_as(first, second, sel, sizeof sel);
    zc_want(strcmp(sel, zcw("apple-first/as")) == 0,
            "Apple selector fixture did not switch to the earlier tool");
    ap_as_compile(cache, log, first, second, NULL, m);
    zc_disp_in(log, "MISS", "newly executable Apple assembler was served from cache");
    ap_as_compile(cache, log, first, second, NULL, m);
    zc_disp_in(log, "HIT", "unchanged Apple assembler selection did not return to HIT");
    return 0;
}

static int ap_as_unknown(void)
{
    if (ap_file("apple-unknown-compiler",
                "#!/bin/sh\ncase \" $* \" in\n    *' -print-prog-name=as '*) exit 0 ;;\n"
                "esac\nexec cc \"$@\"\n", 0700))
        return 1;
    const char *const args[] = { zcw("apple-unknown-compiler"), "-std=c23",
        "-fno-integrated-as", zcf("-B%s", zcw("apple-as")), "-c", zcw("apple-as.c"),
        "-o", zcw("apple-as.o"), NULL };
    ap_zcc(zcw("apple-as-cache"), zcw("apple-as.log"), NULL, args,
           "Apple missing-fact compile failed");
    zc_disp_in(zcw("apple-as.log"), "UNKEY",
               "missing Apple assembler fact did not fail cache admission");
    return 0;
}

int zc_sec_apple(void)
{
    if (!zc_on("Darwin"))
        return 0;
    if (ap_backend_main() || ap_race_run(&ap_backend_race_spec) || ap_backend_path() ||
        ap_backend_unknown())
        return 1;
    const char *const av[] = { "cc", "-print-prog-name=as", NULL };
    ap_out(av, ap_as, sizeof ap_as);
    if (access(ap_as, X_OK) != 0) {
        zc_fail("Apple assembler could not be resolved");
        return 0;
    }
    return ap_as_basic() || ap_race_run(&ap_as_race_spec) || ap_as_select() || ap_as_unknown();
}
