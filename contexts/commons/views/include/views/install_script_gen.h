/* Auto-generated from platform/packaging/install/install_from_source.sh -- do not edit.
 * Regenerate: make templates */

#ifndef ZCL_VIEWS_INSTALL_SCRIPT_GEN_H
#define ZCL_VIEWS_INSTALL_SCRIPT_GEN_H

static const char INSTALL_FROM_SOURCE_SH_0[] =
    "#!/bin/sh\n# Copyright 2026 Rhett Creighton - Apache License 2.0\n#\n# install_from_source.sh —"
    " the source-build installer served at\n# /install.sh (core/modules/net/include/net/site_routes.de"
    "f), so\n# `curl -fsSL https://<site>/install.sh | sh` builds a Z23 node from\n# source and downlo"
    "ads NO BINARY: it clones the source tree over git and\n# compiles it locally with the toolchain a"
    "lready on this machine.\n#\n# This is a SEPARATE, simpler front door from the digest-verified bin"
    "ary\n# bootstrap (platform/packaging/install/install.sh + tools/install/z23_bootstrap.c). That\n#"
    " chain fetches one prebuilt binary after checking its SHA-256 against a\n# pin baked into the rel"
    "ease, and stays unpublished until its signing\n# gate is met (docs/work/BOOTSTRAP_PLAN.md:299-309"
    "). Nothing here reads\n# that pin or touches that chain.\n#\n# POSIX /bin/sh only: no bash-isms, "
    "and this script never reads its own\n# stdin (it is meant to run piped from curl, and consuming t"
    "hat pipe\n# would eat the rest of the script). It never refers to $0 either, since\n# a piped scr"
    "ipt has no reliable name.\n\nset -euf\n\nREPO_URL=\"https://github.com/z23c/z23.git\"\nSRC=\"${Z2"
    "3_SRC:-$HOME/z23}\"\n# The server that serves this file rewrites this literal placeholder to\n# i"
    "ts own build commit before responding; an empty value means the\n# running node could not name on"
    "e, and this script falls back to main.\nZ23_PIN=\"__Z23_PIN__\"\n\ndie() {\n    echo \"install_fr"
    "om_source: $*\" >&2\n    exit 2\n}\n\nsay() {\n    echo \"install_from_source: $*\" >&2\n}\n\nnee"
    "d() {\n    command -v \"$1\" >/dev/null 2>&1 || die \"missing required command: $1\"\n}\n\n# All "
    "git and build output goes to a log file, not the terminal. Until\n# the clone exists it is a temp"
    " file; it then moves to $SRC/build/install.log.\n# A failed step shows the last 20 lines of it an"
    "d exits non-zero.\nTMPLOG=$(mktemp \"${TMPDIR:-/tmp}/z23-install.XXXXXX\") ||\n    die \"cannot c"
    "reate a temporary log file\"\nLOG=\"$TMPLOG\"\n# The temp log never outlives the script, on succe"
    "ss or on any failure.\ntrap 'rm -f \"$TMPLOG\"' EXIT\n\nrun() {\n    \"$@\" >>\"$LOG\" 2>&1 || {\n"
    "        say \"FAILED: $*\"\n        say \"last 20 lines of the log:\"\n        tr '\\r' '\\n' <\""
    "$LOG\" | tail -n 20 >&2\n        [ \"$LOG\" = \"$TMPLOG\" ] || say \"full log: $LOG\"\n        ex"
    "it 1\n    }\n}\n\nsay \"1/4 Checking tools (git, make, a C23 compiler)...\"\nneed git\nneed make\n"
    "\ncc_ok=\"\"\nprobe=\"./.z23-cc-probe.$$\"\nmkdir -p \"$probe\" 2>/dev/null ||\n    die \"cannot "
    "create a working directory to probe the C compiler\"\nprintf 'int main(void){return 0;}\\n' >\"$p"
    "robe/probe.c\"\nfor candidate in cc gcc clang; do\n    command -v \"$candidate\" >/dev/null 2>&1 "
    "|| continue\n    if \"$candidate\" -std=c23 -o \"$probe/probe\" \"$probe/probe.c\" \\\n          "
    "  >/dev/null 2>&1; then\n        cc_ok=\"$candidate\"\n        break\n    fi\ndone\nrm -rf \"$pro"
    "be\"\n[ -n \"$cc_ok\" ] ||\n    die \"missing required command: a C compiler (cc, gcc, or"
    " clang) accepting -std=c23\"\n\nif [ -d \"$SRC\" ]; then\n    [ -d \"$SRC/.git\" ] ||\n        di"
    "e \"$SRC exists and is not a z23 git clone; set Z23_SRC to pic";
static const char INSTALL_FROM_SOURCE_SH_1[] =
    "k another path\"\n    url=$(git -C \"$SRC\" remote get-url origin 2>/dev/null || echo \"\")\n    "
    "case \"$url\" in\n    \"$REPO_URL\" | \"${REPO_URL%.git}\") ;;\n    *)\n        die \"$SRC is a g"
    "it clone of '$url', not $REPO_URL; set Z23_SRC to pick another path\"\n        ;;\n    esac\n    "
    "say \"2/4 Getting the source: updating the existing clone in $SRC...\"\n    run git -C \"$SRC\" f"
    "etch origin\nelse\n    say \"2/4 Getting the source: cloning $REPO_URL into $SRC...\"\n    run gi"
    "t clone \"$REPO_URL\" \"$SRC\"\nfi\n\nif [ -n \"$Z23_PIN\" ]; then\n    echo \"checking out pinne"
    "d commit $Z23_PIN\" >>\"$LOG\"\n    run git -C \"$SRC\" checkout \"$Z23_PIN\"\nelse\n    echo \"n"
    "o commit pin was served; building main instead\" >>\"$LOG\"\n    run git -C \"$SRC\" checkout mai"
    "n\n    run git -C \"$SRC\" pull --ff-only origin main\nfi\n\nmkdir -p \"$SRC/build\" || die \"can"
    "not create $SRC/build\"\ncat \"$LOG\" >>\"$SRC/build/install.log\"\nrm -f \"$TMPLOG\"\nLOG=\"$SRC"
    "/build/install.log\"\n\njobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)\nsay \"3/4 Buildi"
    "ng (several minutes the first time; full output: $LOG)...\"\nrun env CC=\"$cc_ok\" make -C \"$SRC"
    "\" setup\nrun env CC=\"$cc_ok\" make -C \"$SRC\" -j\"$jobs\" z23\n\nsay \"4/4 Done\"\necho \"\"\n"
    "echo \"Source:  $SRC\"\necho \"Binary:  $SRC/build/bin/z23\"\necho \"Start:   (cd \\\"$SRC\\\" &&"
    " build/bin/z23)\"\necho \"Check:   (cd \\\"$SRC\\\" && build/bin/z23 status)   # in a second term"
    "inal\"\necho \"Log:     $LOG\"\necho \"Next steps: https://z23.sh/start\"\necho \"Want to contrib"
    "ute? Read .github/CONTRIBUTING.md in $SRC, then post a claim in board room contrib (https://z23.s"
    "h/start).\"\n";

static char _INSTALL_FROM_SOURCE_SH_buf[4529];
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
