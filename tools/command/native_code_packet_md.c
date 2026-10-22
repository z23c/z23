/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * code.packet rendering: the packet name, the size class, the exact gate
 * command lines, the lint traps a packet's paths trigger, and the markdown
 * document in PACKET_TEMPLATE field order. Pure string work over the facts
 * the gatherers already hold; it reads nothing and decides nothing about the
 * tree. See native_code_packet_priv.h. */

#include "command/native_code_packet_priv.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* "fix the download hold" -> "fix-the-download-hold": at most six words and
 * forty characters of [a-z0-9], so one goal always names one packet. */
void pk_slug(const char *goal, char *out, size_t cap)
{
    size_t n = 0;
    int words = 0;
    bool in_word = false;
    for (const char *p = goal; *p && words <= 6 && n + 2 < cap && n < 40; p++) {
        if (isalnum((unsigned char)*p)) {
            if (!in_word && ++words > 6)
                break;
            in_word = true;
            out[n++] = (char)tolower((unsigned char)*p);
        } else if (in_word) {
            in_word = false;
            out[n++] = '-';
        }
    }
    while (n > 0 && out[n - 1] == '-') n--;
    if (n == 0) {
        (void)snprintf(out, cap, "packet");
        return;
    }
    out[n] = '\0';
}

const char *pk_size_class(int max_dependents)
{
    if (max_dependents <= 10) return "S";
    if (max_dependents <= 100) return "M";
    return "L";
}

size_t pk_gate_lines(const struct pk_facts *f, char (*out)[PK_GATE_LEN])
{
    size_t n = 0;
    if (f->ngroup > 0) {
        int len = snprintf(out[n], PK_GATE_LEN,
                           "timeout 2400 devbuild --wait make t-fast-exact "
                           "ONLY=");
        for (int i = 0; i < f->ngroup && len > 0 && len < PK_GATE_LEN - 100;
             i++)
            len += snprintf(out[n] + len, PK_GATE_LEN - (size_t)len, "%s%s",
                            i ? "," : "", f->group[i].id);
        n++;
    }
    (void)snprintf(out[n++], PK_GATE_LEN,
                   "timeout 2400 devbuild --wait make z23-dev && timeout 600 "
                   "devbuild --wait make check-capability-closure");
    (void)snprintf(out[n++], PK_GATE_LEN,
                   "timeout 2400 devbuild --wait make docs-capability-"
                   "inventory fix-doc-counts");
    (void)snprintf(out[n++], PK_GATE_LEN,
                   "env -u GIT_EDITOR -u GIT_OPTIONAL_LOCKS timeout 2400 "
                   "devbuild --wait make lint");
    return n;
}

size_t pk_trap_lines(unsigned mask, char (*out)[PK_TRAP_LEN])
{
    static const struct {
        unsigned bit;
        const char *text;
    } k_traps[] = {
        { PK_TRAP_TESTS,
          "tests: never assert wall-clock time (check-no-wallclock-assertion); "
          "a new test must fail with the fix reverted and pass with it." },
        { PK_TRAP_COMMAND,
          "tools/command: a new unit needs a module_capabilities.def row, an "
          "agent_impact_rules.def row and cyclomatic complexity <= 15 per "
          "function; a new leaf needs no remote_command_classes.def row: no row is "
          "NEVER, and only a permit takes one." },
        { PK_TRAP_DEF,
          "a .def edit changes generated docs: run docs-capability-inventory "
          "and fix-doc-counts, then commit what changed." },
        { PK_TRAP_DOCS,
          "docs: no operator paths (check-no-operator-paths) and no inline "
          "paths the doc gate cannot resolve (check-doc-inline-paths)." },
        { PK_TRAP_CORE,
          "core/ is sealed: a core/ edit is a consensus change and is out of "
          "scope for a packet builder." },
        { PK_TRAP_ARM,
          "an excerpt carries #if/#ifdef arms: keep one definition per "
          "function per translation unit and put the #ifdef inside the body "
          "(check-arm-symbol-single)." },
    };
    size_t n = 0;
    for (size_t i = 0; i < sizeof(k_traps) / sizeof(k_traps[0]); i++)
        if ((mask & k_traps[i].bit) != 0)
            (void)snprintf(out[n++], PK_TRAP_LEN, "%s", k_traps[i].text);
    (void)snprintf(out[n++], PK_TRAP_LEN,
                   "git add -A before the final lint: an untracked new file or "
                   "a stale generated file is the commonest lint failure.");
    return n;
}

static void pk_md_route(struct pk_sb *sb, const struct pk_facts *f)
{
    if (f->nroute == 0)
        pk_sb_add(sb, "ROUTE:   (no touched file)\n");
    for (int i = 0; i < f->nroute; i++)
        pk_sb_add(sb, "%s%s -> %s%s\n", i ? "         " : "ROUTE:   ",
                  f->route[i].file, f->route[i].route,
                  f->route[i].consensus_risk
                      ? "  [consensus surface: heaviest proof]" : "");
}

static void pk_md_acceptance(struct pk_sb *sb, const struct pk_facts *f)
{
    pk_sb_add(sb, "ACCEPTANCE:\n  Registered groups that must run (covering "
                  "the touched files):\n");
    if (f->ngroup == 0)
        pk_sb_add(sb, "    (none resolved: the route above is the floor)\n");
    for (int i = 0; i < f->ngroup; i++) {
        pk_sb_add(sb, "    %-40s", f->group[i].id);
        if (f->group[i].catalog_line > 0)
            pk_sb_add(sb, " tools/dev/test_group_catalog.def:%d",
                      f->group[i].catalog_line);
        else
            pk_sb_add(sb, " catalog row: not located in this tree");
        pk_sb_add(sb, "   host: %s\n", f->group[i].need);
    }
    pk_sb_add(sb,
        "  Red then green: a new or changed test must fail with the fix "
        "reverted and pass with it; say how you showed it.\n"
        "  Lint-fast: run `make lint-fast` while iterating; the full lint is "
        "the last gate.\n"
        "  Performance: state a measured number for any hot path you touch; "
        "never assert wall-clock time in a test.\n"
        "  Presentation: operator-facing text is plain, aligned and free of "
        "host names, addresses and absolute paths.\n"
        "  Gates (devbuild --wait, output to build/scratch/, read with tail):"
        "\n");
    char gates[PK_GATES][PK_GATE_LEN];
    size_t ng = pk_gate_lines(f, gates);
    for (size_t i = 0; i < ng; i++)
        pk_sb_add(sb, "    %s\n", gates[i]);
}

void pk_md_document(struct pk_sb *doc, const struct pk_input *in,
                    const struct pk_facts *f, const struct pk_sb *files,
                    const struct pk_sb *keep, const struct pk_sb *authority,
                    const struct pk_sb *notes)
{
    pk_sb_add(doc, "# PACKET %s\n", f->name);
    pk_md_route(doc, f);
    pk_sb_add(doc, "BASE:    %s  source_root_sha3=%s  dep_root_sha3=%s\n",
              f->head[0] ? f->head : "HEAD-unavailable", f->source_hex,
              f->dep_hex);
    pk_sb_add(doc,
              "SIZE:    %s  (%d file(s), %d symbol(s), %d excerpt line(s); "
              "most dependents of one file: %d; S <= 10, M <= 100, else L)\n",
              pk_size_class(f->max_dependents), f->ntouch, in->nsym,
              f->excerpt_lines, f->max_dependents);
    pk_sb_add(doc, "GOAL:    %s\n\n", in->goal);
    pk_sb_add(doc, "FILES AND EXACT EXCERPTS:\n");
    pk_sb_raw(doc, files->p ? files->p : "", files->len);
    pk_sb_add(doc, "\nCHANGE:\n  %s\n\n",
              in->change && in->change[0] ? in->change : "(none given)");
    pk_sb_add(doc, "KEEP UNCHANGED:\n");
    pk_sb_raw(doc, keep->p ? keep->p : "", keep->len);
    pk_sb_add(doc, "\n");
    pk_md_acceptance(doc, f);
    pk_sb_add(doc, "\nAUTHORITY:\n");
    pk_sb_raw(doc, authority->p ? authority->p : "", authority->len);
    pk_sb_add(doc, "\nPACKER NOTES:\n");
    pk_sb_raw(doc, notes->p ? notes->p : "", notes->len);
}
