/* Auto-generated from platform/packaging/install/install_from_source.sh -- do not edit.
 * Regenerate: make templates */

#ifndef ZCL_VIEWS_INSTALL_SCRIPT_GEN_H
#define ZCL_VIEWS_INSTALL_SCRIPT_GEN_H

static const char INSTALL_FROM_SOURCE_SH_0[] =
    "#!/bin/sh\n# Copyright 2026 Rhett Creighton - Apache License 2.0\n#\n# install_from_source.sh —"
    " the source-build installer served at /install.sh\n# (core/modules/net/include/net/site_routes.de"
    "f): `curl -fsSL\n# https://<site>/install.sh | sh` clones the source over git and compiles it\n# "
    "with this machine's toolchain. It downloads NO BINARY and never touches the\n# digest-pinned bina"
    "ry bootstrap (install.sh + tools/install/z23_bootstrap.c).\n#\n# POSIX /bin/sh only. It never rea"
    "ds its own stdin (it runs piped from curl,\n# so that would eat the script) and never names $0 (a"
    " pipe has no name).\n\nset -euf\n\nREPO_URL=\"https://github.com/z23c/z23.git\"\nSRC=\"${Z23_SRC:"
    "-$HOME/z23}\"\n# The server that serves this file rewrites this literal placeholder to\n# its own"
    " build commit before responding; an empty value means the\n# running node could not name one, and"
    " this script falls back to main.\nZ23_PIN=\"__Z23_PIN__\"\n\ndie() {\n    echo \"install_from_sou"
    "rce: $*\" >&2\n    exit 2\n}\n\nsay() {\n    echo \"install_from_source: $*\" >&2\n}\n\nneed() {\n"
    "    command -v \"$1\" >/dev/null 2>&1 || die \"missing required command: $1\"\n}\n\n# All git and"
    " build output goes to a log file, not the terminal. Until\n# the clone exists it is a temp file; "
    "it then moves to $SRC/build/install.log.\n# A failed step shows the last 20 lines of it and exits"
    " non-zero.\nTMPLOG=$(mktemp \"${TMPDIR:-/tmp}/z23-install.XXXXXX\") ||\n    die \"cannot create a"
    " temporary log file\"\nLOG=\"$TMPLOG\"\n# The temp log never outlives the script, on success or o"
    "n any failure.\ntrap 'rm -f \"$TMPLOG\"' EXIT\n\nrun() {\n    \"$@\" >>\"$LOG\" 2>&1 || {\n      "
    "  say \"FAILED: $*\"\n        say \"last 20 lines of the log:\"\n        tr '\\r' '\\n' <\"$LOG\""
    " | tail -n 20 >&2\n        [ \"$LOG\" = \"$TMPLOG\" ] || say \"full log: $LOG\"\n        exit 1\n"
    "    }\n}\n\nsay \"1/4 Checking tools (git, make, a C23 compiler)...\"\nneed git\nneed make\n\ncc_"
    "ok=\"\"\nprobe=\"./.z23-cc-probe.$$\"\nmkdir -p \"$probe\" 2>/dev/null ||\n    die \"cannot creat"
    "e a working directory to probe the C compiler\"\nprintf 'int main(void){return 0;}\\n' >\"$probe/"
    "probe.c\"\nfor candidate in cc gcc clang; do\n    command -v \"$candidate\" >/dev/null 2>&1 || co"
    "ntinue\n    if \"$candidate\" -std=c23 -o \"$probe/probe\" \"$probe/probe.c\" \\\n            >/d"
    "ev/null 2>&1; then\n        cc_ok=\"$candidate\"\n        break\n    fi\ndone\nrm -rf \"$probe\"\n"
    "[ -n \"$cc_ok\" ] ||\n    die \"missing required command: a C compiler (cc, gcc, or clang) accept"
    "ing -std=c23\"\n\nif [ -d \"$SRC\" ]; then\n    [ -d \"$SRC/.git\" ] ||\n        die \"$SRC exist"
    "s and is not a z23 git clone; set Z23_SRC to pick another path\"\n    url=$(git -C \"$SRC\" remot"
    "e get-url origin 2>/dev/null || echo \"\")\n    case \"$url\" in\n    \"$REPO_URL\" | \"${REPO_UR"
    "L%.git}\") ;;\n    *)\n        die \"$SRC is a git clone of '$url', not $REPO_URL; set Z23_SRC to"
    " pick another path\"\n        ;;\n    esac\n    say \"2/4 Getting the source: updating th"
    "e existing clone in $SRC...\"\n    run git -C \"$SRC\" fetch origin\nelse\n    say \"2/4 Getting "
    "the source: cloning $REPO_URL into $SRC...\"\n    run git clone \"$REPO_URL\" \"$SRC\"\nf";
static const char INSTALL_FROM_SOURCE_SH_1[] =
    "i\n\nif [ -n \"$Z23_PIN\" ]; then\n    echo \"checking out pinned commit $Z23_PIN\" >>\"$LOG\"\n "
    "   run git -C \"$SRC\" checkout \"$Z23_PIN\"\nelse\n    echo \"no commit pin was served; building"
    " main instead\" >>\"$LOG\"\n    run git -C \"$SRC\" checkout main\n    run git -C \"$SRC\" pull -"
    "-ff-only origin main\nfi\n\nmkdir -p \"$SRC/build\" || die \"cannot create $SRC/build\"\ncat \"$L"
    "OG\" >>\"$SRC/build/install.log\"\nrm -f \"$TMPLOG\"\nLOG=\"$SRC/build/install.log\"\n\njobs=$(ge"
    "tconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)\nsay \"3/4 Building (several minutes the first tim"
    "e; full output: $LOG)...\"\nrun env CC=\"$cc_ok\" make -C \"$SRC\" setup\nrun env CC=\"$cc_ok\" m"
    "ake -C \"$SRC\" -j\"$jobs\" z23\n\nsay \"4/4 Done\"\necho \"\"\necho \"Source:  $SRC\"\necho \"Bi"
    "nary:  $SRC/build/bin/z23\"\necho \"Start:   (cd \\\"$SRC\\\" && build/bin/z23)\"\necho \"Check: "
    "  (cd \\\"$SRC\\\" && build/bin/z23 status)   # in a second terminal\"\necho \"Log:     $LOG\"\ne"
    "cho \"Next steps: https://z23.sh/start\"\necho \"Want to contribute? Read .github/CONTRIBUTING.md"
    " in $SRC, then post a claim in board room contrib (https://z23.sh/start).\"\n";

static char _INSTALL_FROM_SOURCE_SH_buf[4047];
__attribute__((unused))
static const char *INSTALL_FROM_SOURCE_SH_get(void) {
    size_t off = 0;
    size_t l0 = __builtin_strlen(INSTALL_FROM_SOURCE_SH_0);
    __builtin_memcpy(_INSTALL_FROM_SOURCE_SH_buf + off, INSTALL_FROM_SOURCE_SH_0, l0); off += l0;
    size_t l1 = __builtin_strlen(INSTALL_FROM_SOURCE_SH_1);
    __builtin_memcpy(_INSTALL_FROM_SOURCE_SH_buf + off, INSTALL_FROM_SOURCE_SH_1, l1); off += l1;
    _INSTALL_FROM_SOURCE_SH_buf[off] = 0;
    return _INSTALL_FROM_SOURCE_SH_buf;
}
#define INSTALL_FROM_SOURCE_SH (INSTALL_FROM_SOURCE_SH_get())

#endif
