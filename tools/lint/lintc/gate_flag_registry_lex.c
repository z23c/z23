/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-flag-registry
 * Third file of the check-flag-registry family: decides whether a read
 * the scanner's regexes recognized is a REAL read. gate_flag_registry.c
 * finds getenv/env_or/env_int_or/zcl_env_positive_int and ${...} matches as text; this file
 * lexes just enough C (comments, literals, #if 0) and shell/Makefile
 * (comment-opening '#') to tell code from a mention, which is what a
 * "first use <path>:auto" pointer is proved against.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <string.h>
#include "gate_flag_registry_priv.h"

/* The two regexes match text, not code: a getenv() call quoting a ZCL_
 * name inside a C comment, or inside a string literal that merely quotes
 * one, matches too. That is fine for the registered/stale question (a
 * mention keeps a row alive, as it always has), but not for a
 * "<path>:auto" first-use pointer, which claims "this file really reads
 * the flag". This is why :auto was shell-only when it landed: its
 * comment test blanks everything after a '#', and in C a '#' starts a
 * directive, not a comment — applied to C it would reject a read in a
 * macro body and accept a read in a comment.
 *
 * So for C a read counts toward :auto only when a small lexer, carried
 * line to line through the file, puts the reader token outside every
 * comment (block, line, and a line comment continued by a backslash),
 * string literal, character constant, and `#if 0` region. A literal the
 * lexer misreads (an apostrophe in #error prose, an unterminated string)
 * ends with its own line, so a misreading reaches past that line only if
 * it also swallows a block-comment opener there. */

/* True when the quote at s[i] is a C23 digit separator (1'000'000), not a
 * character constant: the pp-number it sits inside starts with a digit.
 * The u8/u/U/L character-constant prefixes start with a letter. */
static int fr_c_digit_sep(const char *s, size_t i)
{
    size_t j = i;
    while (j > 0 && (isalnum((unsigned char)s[j - 1]) || s[j - 1] == '_'
                     || s[j - 1] == '\'' || s[j - 1] == '.'))
        j--;
    return j < i && isdigit((unsigned char)s[j])
        && isalnum((unsigned char)s[i + 1]);
}

static size_t fr_c_step_code(const char *s, size_t i, int *st)
{
    if (s[i] == '/' && (s[i + 1] == '*' || s[i + 1] == '/')) {
        *st = s[i + 1] == '*' ? FR_BLOCK : FR_LINE;
        return 2;
    }
    if (s[i] == '"')
        *st = FR_STR;
    else if (s[i] == '\'' && !fr_c_digit_sep(s, i))
        *st = FR_CHR;
    return 1;
}

/* Advances the lexer over the token at s[i] (s[i] != '\0'); returns how
 * many bytes it consumed — two for a comment delimiter or an escape. */
static size_t fr_c_step(const char *s, size_t i, int *st)
{
    switch (*st) {
    case FR_BLOCK:
        if (s[i] == '*' && s[i + 1] == '/') {
            *st = FR_CODE;
            return 2;
        }
        return 1;
    case FR_LINE:
        return 1;
    case FR_STR:
    case FR_CHR:
        if (s[i] == '\\' && s[i + 1])
            return 2;
        if (s[i] == (*st == FR_STR ? '"' : '\''))
            *st = FR_CODE;
        return 1;
    default:
        return fr_c_step_code(s, i, st);
    }
}

/* The lexer state at byte off of line, which it entered in state st. */
static int fr_c_state_at(const char *line, size_t off, int st)
{
    size_t i = 0;
    while (i < off && line[i])
        i += fr_c_step(line, i, &st);
    return st;
}

/* The state the next line starts in: a block comment carries on; a line
 * comment or a literal carries only across a backslash-newline splice (an
 * unterminated literal is invalid C and ends with its line). */
int frl_c_state_after(const char *line, int st)
{
    size_t n = strlen(line);
    st = fr_c_state_at(line, n, st);
    if (st == FR_CODE || st == FR_BLOCK)
        return st;
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
        n--;
    return (n > 0 && line[n - 1] == '\\') ? st : FR_CODE;
}

/* True when p begins directive word w (followed by a non-identifier). */
static int fr_c_word(const char *p, const char *w)
{
    size_t n = strlen(w);
    return strncmp(p, w, n) == 0 && !isalnum((unsigned char)p[n])
        && p[n] != '_';
}

/* True when a directive's condition (text after `#if`/`#elif`) is the
 * literal 0. Anything else — `0 || X` included — is read as live, the
 * direction in which a mistake cannot hide a real read. */
static int fr_c_cond_zero(const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != '0')
        return 0;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    return *p == '\0' || (p[0] == '/' && (p[1] == '/' || p[1] == '*'));
}

/* The directive word after a line's '#' (blanks skipped), or NULL when
 * the line is not a preprocessor directive. */
static const char *fr_c_directive(const char *line)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p++ != '#')
        return NULL;
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

/* The `#if 0` depth after a line that begins in code: 0 is live code;
 * nested #if/#ifdef/#ifndef count up, #endif down, and an outermost
 * #else (or an #elif that is not itself 0) reopens live code. */
int frl_c_if0(const char *line, int depth)
{
    const char *p = fr_c_directive(line);
    if (!p)
        return depth;
    int is_if = fr_c_word(p, "if");
    if (depth == 0)
        return is_if && fr_c_cond_zero(p + 2);
    if (is_if || fr_c_word(p, "ifdef") || fr_c_word(p, "ifndef"))
        return depth + 1;
    if (fr_c_word(p, "endif"))
        return depth - 1;
    if (depth > 1)
        return depth;
    if (fr_c_word(p, "else"))
        return 0;
    return fr_c_word(p, "elif") ? fr_c_cond_zero(p + 4) : depth;
}

/* The first '#' in a shell line that can open a comment: one that starts a
 * word (line start, or after a blank or ;&|() ). ${#arr[@]} and "$#" are
 * not comments. A '#' right after a quote also counts, so a name inside
 * '#...' generated-script text is never taken for a read — a mistake here
 * can only hide a read. Makefile text keeps any '#': make strips a comment
 * wherever it starts. */
static const char *fr_sh_comment(const char *text, int makefile)
{
    for (const char *p = strchr(text, '#'); p; p = strchr(p + 1, '#'))
        if (makefile || p == text || strchr(" \t;&|()'\"", p[-1]))
            return p;
    return NULL;
}

static int fr_is_makefile(const char *path)
{
    const char *slash = strrchr(path, '/');
    return strcmp(slash ? slash + 1 : path, "Makefile") == 0;
}

/* True when the read whose match starts at text[off] is real code: for C,
 * lexed code outside #if 0; for shell and Makefile, before any comment. */
int frl_read_is_real(const struct fr_line *ln, size_t off,
                      const char *name)
{
    if (ln->is_c)
        return ln->if0 == 0
            && fr_c_state_at(ln->text, off, ln->c_state) == FR_CODE;
    const char *hash = fr_sh_comment(ln->text, fr_is_makefile(ln->path));
    const char *name_at = strstr(ln->text + off, name);
    return name_at && (!hash || hash > name_at);
}

