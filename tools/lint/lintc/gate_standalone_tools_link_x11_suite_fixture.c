/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: fixture construction for the X11 standalone-tools selftest port
 * (gate_standalone_tools_link_x11.c). Creates the private scratch tree,
 * copies the vendor X11 headers, writes the fake compiler, helper scripts
 * and Makefile fragments byte-for-byte as DATA (same bytes the shell script
 * wrote), resolves cc through PATH, and builds the stub libX11.so.6. Every
 * subprocess runs via fork plus execvp with an argv array.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_proc.h"
#include "gate_standalone_tools_link_x11_suite.h"

const char k_stl_x11_good[] =
    "#include <X11/Xlib.h>\n"
    "#ifndef PR72_PLATFORM\n"
    "#error missing platform flag\n"
    "#endif\n"
    "int main(void){return XOpenDisplay(0)==0;}\n";

static const char k_mk_hdr[] =
    "CC = cc\n"
    "ZCL_PLATFORM_CPPFLAGS = -DPR72_PLATFORM=1\n"
    "BIN_DIR = build/bin\n"
    "FUZZ_TARGETS = $(BIN_DIR)/fuzz_block $(BIN_DIR)/fuzz_script $(BIN_DIR)/fuzz_p2p "
    "$(BIN_DIR)/fuzz_http $(BIN_DIR)/fuzz_compactblock $(BIN_DIR)/fuzz_snapshot "
    "$(BIN_DIR)/fuzz_tx_bundle $(BIN_DIR)/fuzz_rom_manifest $(BIN_DIR)/fuzz_overlay "
    "$(BIN_DIR)/fuzz_ecdsa $(BIN_DIR)/fuzz_zcode_commons $(BIN_DIR)/fuzz_zcode_dht "
    "$(BIN_DIR)/fuzz_zcode_science $(BIN_DIR)/fuzz_mesh_status_proto "
    "$(BIN_DIR)/fuzz_semantic_manifest\n"
    "fuzz-ci: check-fuzz-ci-tools $(FUZZ_TARGETS)\n";

static const char k_mk_rule[] = "$(BIN_DIR)/%s:\n\t@mkdir -p build/bin; touch $@\n";

static const char *const k_ci_names[] = {
    "fuzz_zcode_commons", "fuzz_zcode_dht", "fuzz_zcode_science",
    "fuzz_mesh_status_proto", "fuzz_semantic_manifest",
};

static const char *const k_dirs[] = {
    "tools/lint", "tools/agent", "vendor/x11",
    "platform/modules/platform/tests", "build/bin",
};

/* The fake fixture compiler, copied verbatim from the shell heredoc. */
static const char k_compiler[] =
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    "printf '%s\\n' \"$*\" >> \"$PR72_CC_LOG\"\n"
    "runtime=0; cover=0\n"
    "for arg in \"$@\"; do\n"
    "    [[ \"$arg\" != -Wl,-l:libX11.so.6 ]] || runtime=1\n"
    "    [[ \"$arg\" != tools/native_ui_driver.c ]] || cover=1\n"
    "done\n"
    "output=\"\"; next_output=0\n"
    "for arg in \"$@\"; do\n"
    "    if ((next_output)); then output=\"$arg\"; next_output=0; fi\n"
    "    [[ \"$arg\" != -o ]] || next_output=1\n"
    "done\n"
    "case \"${PR72_FAULT:-}\" in\n"
    "    baseline-run)\n"
    "        if ((!runtime && !cover)); then\n"
    "            printf '#!/usr/bin/env bash\\nexit 7\\n' > \"$output\"\n"
    "            chmod +x \"$output\"\n"
    "            exit 0\n"
    "        fi ;;\n"
    "    partial-baseline)\n"
    "        if ((!runtime && !cover)); then\n"
    "            printf '#!/usr/bin/env bash\\nexit 0\\n' > \"$output\"\n"
    "            chmod +x \"$output\"\n"
    "            exit 7\n"
    "        fi ;;\n"
    "    partial-object)\n"
    "        if ((cover)); then\n"
    "            printf 'partial object output' > \"$output\"\n"
    "            exit 7\n"
    "        fi ;;\n"
    "    compile) echo 'fixture compiler failure' >&2; exit 1 ;;\n"
    "    wrong-target) \"$REAL_CC\" \"$@\" -D__linux__=0 -U__linux__; exit $? ;;\n"
    "    generic-link) if ((runtime)); then echo 'ld: internal error' >&2; exit 1; fi ;;\n"
    "    mixed-link) if ((runtime)); then echo 'ld: cannot find -l:libX11.so.6: "
    "No such file or directory' >&2; echo 'ld: internal error' >&2; exit 1; fi ;;\n"
    "    object) if ((cover)); then exit 1; fi ;;\n"
    "    empty-object) if ((cover)); then exit 0; fi ;;\n"
    "esac\n"
    "if ((runtime)) && [[ \"${PR72_FAULT:-}\" != present ]]; then\n"
    "    args=()\n"
    "    for arg in \"$@\"; do\n"
    "        [[ \"$arg\" != -Wl,-l:libX11.so.6 ]] || "
    "arg=-Wl,-l:zcl_pr72_missing_fixture.so\n"
    "        args+=(\"$arg\")\n"
    "    done\n"
    "    set +e\n"
    "    \"$REAL_CC\" \"${args[@]}\" 2>\"$PR72_CC_LOG.link\"\n"
    "    rc=$?\n"
    "    set -e\n"
    "    sed 's/zcl_pr72_missing_fixture.so/libX11.so.6/g' "
    "\"$PR72_CC_LOG.link\" >&2\n"
    "    exit \"$rc\"\n"
    "fi\n"
    "exec \"$REAL_CC\" \"$@\" -L\"$PR72_FIXTURE_LIB\"\n";

static int x11_exec(char *const av[])
{
    struct lcp_spec sp = { .argv = av, .mode = LCP_PASS };
    int code = 0;
    return lcp_run(&sp, NULL, &code) == 0 ? code : -1;
}

/* Resolve cc through PATH, as the script's command -v cc did. */
static int x11_which(char *out, size_t cap)
{
    const char *p = getenv("PATH");
    char part[STL_X11_PATH];
    if (!p)
        return 1;
    while (*p) {
        size_t n = 0;
        while (p[n] && p[n] != ':')
            n++;
        if (n == 0 || n >= sizeof part) {
            p += n;
            if (*p == ':')
                p++;
            continue;
        }
        memcpy(part, p, n);
        part[n] = '\0';
        if (!ovf(snprintf(out, cap, "%s/cc", part), cap) &&
            access(out, X_OK) == 0)
            return 0;
        p += n;
        if (*p == ':')
            p++;
    }
    return 1;
}

static int x11_paths(struct stl_x11_ctx *c)
{
    if (ovf(snprintf(c->fixture, sizeof c->fixture, "%s/repo", c->tmp),
            sizeof c->fixture) ||
        ovf(snprintf(c->out, sizeof c->out, "%s/out", c->tmp), sizeof c->out) ||
        ovf(snprintf(c->err, sizeof c->err, "%s/err", c->tmp), sizeof c->err) ||
        ovf(snprintf(c->cclog, sizeof c->cclog, "%s/compiler.log", c->tmp),
            sizeof c->cclog) ||
        ovf(snprintf(c->mkgood, sizeof c->mkgood, "%s/Makefile.good", c->tmp),
            sizeof c->mkgood) ||
        ovf(snprintf(c->mk, sizeof c->mk, "%s/Makefile", c->fixture),
            sizeof c->mk) ||
        ovf(snprintf(c->ccbin, sizeof c->ccbin, "%s/bin/compiler", c->tmp),
            sizeof c->ccbin) ||
        ovf(snprintf(c->driver, sizeof c->driver,
                     "%s/tools/native_ui_driver.c", c->fixture),
            sizeof c->driver))
        return 2;
    return 0;
}

static int x11_mk_dirs(struct stl_x11_ctx *c)
{
    char p[STL_X11_PATH];
    for (size_t i = 0; i < sizeof k_dirs / sizeof k_dirs[0]; i++) {
        if (ovf(snprintf(p, sizeof p, "%s/%s", c->fixture, k_dirs[i]),
                 sizeof p) ||
            csr_mkdirs(p) != 0)
            return 1;
    }
    if (ovf(snprintf(p, sizeof p, "%s/bin", c->tmp), sizeof p) ||
        csr_mkdirs(p) != 0)
        return 1;
    if (ovf(snprintf(p, sizeof p, "%s/lib", c->tmp), sizeof p) ||
        csr_mkdirs(p) != 0)
        return 1;
    return 0;
}

static int x11_copy_vendor(struct stl_x11_ctx *c)
{
    char dst[STL_X11_PATH];
    if (ovf(snprintf(dst, sizeof dst, "%s/vendor/x11", c->fixture), sizeof dst))
        return 2;
    char *av[] = { (char *)"cp", (char *)"-R", (char *)"vendor/x11/include",
                   dst, NULL };
    return x11_exec(av) == 0 ? 0 : 1;
}

static int x11_write_tools(struct stl_x11_ctx *c)
{
    char good[STL_X11_PATH], rcpt[STL_X11_PATH];
    char wa[STL_X11_PATH];
    if (ovf(snprintf(good, sizeof good, "%s/good.c", c->tmp), sizeof good) ||
        csr_write(good, k_stl_x11_good) != 0 ||
        csr_write(c->driver, k_stl_x11_good) != 0)
        return 1;
    if (ovf(snprintf(rcpt, sizeof rcpt, "%s/tools/agent/gate-receipt.sh",
                     c->fixture), sizeof rcpt) ||
        csr_write(rcpt, "#!/usr/bin/env bash\necho fixture-receipt-helper\n") != 0 ||
        chmod(rcpt, 0755) != 0)
        return 1;
    if (ovf(snprintf(wa, sizeof wa,
                     "%s/platform/modules/platform/tests/windows_acceptance.mk",
                     c->fixture), sizeof wa) ||
        csr_write(wa, "ZCL_WINDOWS_ACCEPTANCE_TESTS := headless_run\n"
                      "ZCL_WINDOWS_ACCEPTANCE_headless_run_SOURCES := "
                      "tools/dev/windows_headless_run.c\n") != 0)
        return 1;
    return 0;
}

/* The canonical NATIVE_UI_DRIVER_BIN rule, copied from the repository root
 * Makefile so changing the recipe changes the test (the awk pass). */
static int x11_native_block(FILE *out)
{
    FILE *f = fopen("Makefile", "r");
    char line[8192];
    int active = 0;
    if (!f)
        return 1;
    while (fgets(line, sizeof line, f)) {
        if (!active &&
            strncmp(line, "NATIVE_UI_DRIVER_BIN = ", 23) == 0)
            active = 1;
        else if (active && strncmp(line, "# Crash recovery", 16) == 0)
            break;
        if (active && fputs(line, out) == EOF) {
            fclose(f);
            return 1;
        }
    }
    if (ferror(f)) {
        fclose(f);
        return 1;
    }
    fclose(f);
    return 0;
}

static int x11_makefile_write(struct stl_x11_ctx *c, const char *path)
{
    (void)c;
    FILE *out = fopen(path, "w");
    int bad;
    if (!out)
        return 1;
    bad = fputs(k_mk_hdr, out) == EOF;
    for (size_t i = 0; !bad && i < sizeof k_ci_names / sizeof k_ci_names[0];
         i++)
        bad = fprintf(out, k_mk_rule, k_ci_names[i]) < 0;
    if (!bad)
        bad = x11_native_block(out) != 0;
    for (int i = 1; !bad && i <= 20; i++)
        bad = fprintf(out, "$(BIN_DIR)/fixture_%d:\n"
                     "\t@mkdir -p build/bin; touch $@\n", i) < 0;
    if (!bad)
        bad = fputs("$(BIN_DIR)/z23-headless-run.exe:\n"
                    "\t@mkdir -p build/bin; touch $@\n", out) == EOF;
    if (ferror(out))
        bad = 1;
    fclose(out);
    return bad;
}

static int x11_build_lib(struct stl_x11_ctx *c)
{
    char src[STL_X11_PATH], lib[STL_X11_PATH];
    if (ovf(snprintf(src, sizeof src, "%s/x11.c", c->tmp), sizeof src) ||
        ovf(snprintf(lib, sizeof lib, "%s/lib/libX11.so.6", c->tmp),
            sizeof lib))
        return 2;
    char *av[] = { c->realcc, (char *)"-shared", (char *)"-fPIC", src,
                   (char *)"-o", lib, NULL };
    if (csr_write(src, "void *XOpenDisplay(const char *name)"
                       "{(void)name;return 0;}\n") != 0)
        return 1;
    if (x11_exec(av) != 0)
        return 1;
    if (csr_write(c->ccbin, k_compiler) != 0 || chmod(c->ccbin, 0755) != 0)
        return 1;
    return 0;
}

int stl_x11_fixture(struct stl_x11_ctx *c)
{
    memset(c, 0, sizeof *c);
    if (lint_mkdtemp(c->tmp, sizeof c->tmp, "zcl-x11-selftest") != 0)
        return 1;
    if (x11_paths(c) != 0)
        return 2;
    if (lint_self_exe(c->lint, sizeof c->lint) != 0)
        return 1;
    if (x11_which(c->realcc, sizeof c->realcc) != 0)
        return 1;
    if (x11_mk_dirs(c) != 0)
        return 1;
    if (x11_copy_vendor(c) != 0)
        return 1;
    if (x11_write_tools(c) != 0)
        return 1;
    if (x11_makefile_write(c, c->mk) != 0)
        return 1;
    if (x11_makefile_write(c, c->mkgood) != 0)
        return 1;
    return x11_build_lib(c);
}

static int x11_cut(char *line, const char *tok)
{
    char *p = strstr(line, tok);
    if (!p)
        return 0;
    size_t n = strlen(tok);
    memmove(p, p + n, strlen(p + n) + 1);
    return 0;
}

static int x11_swap(char *line, const char *tok, const char *rep)
{
    char *p = strstr(line, tok);
    if (!p)
        return 0;
    size_t tn = strlen(tok), rn = strlen(rep);
    memmove(p + rn, p + tn, strlen(p + tn) + 1);
    memcpy(p, rep, rn);
    return 0;
}

/* Rebuild the fixture Makefile from Makefile.good with one sed transform,
 * mirroring the script's sed invocations. */
int stl_x11_make_from(struct stl_x11_ctx *c, enum stl_x11_mk kind)
{
    FILE *in = fopen(c->mkgood, "r");
    if (!in)
        return 1;
    FILE *out = fopen(c->mk, "w");
    if (!out) {
        fclose(in);
        return 1;
    }
    char line[8192];
    int bad = 0;
    while (!bad && fgets(line, sizeof line, in)) {
        if (kind == STL_X11_MK_DROP_DHT)
            bad = x11_cut(line, " $(BIN_DIR)/fuzz_zcode_dht");
        else if (kind == STL_X11_MK_INVALID_DHT)
            bad = x11_swap(line, "$(BIN_DIR)/fuzz_zcode_dht", "invalid");
        else if (kind == STL_X11_MK_FUZZCI &&
                 strncmp(line, "fuzz-ci:", 8) == 0)
            strcpy(line, "fuzz-ci:\n");
        if (!bad)
            bad = fputs(line, out) == EOF;
    }
    if (ferror(in) || ferror(out))
        bad = 1;
    fclose(in);
    fclose(out);
    return bad;
}
