/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Which work cards a lane already holds. `fleet objectives brief`
 *          hands every caller the top unmet card, so ten agents with no
 *          assignment would all take the same one. A card is taken when some
 *          worktree's branch name or directory name equals the card name or
 *          starts with the card name and '-'; this leaf reads that list from
 *          `git worktree list --porcelain` (no shell, read-only) or from a
 *          fixture file standing in for it. It decides nothing else. */

#include "native_fleet_objectives.h"

#include "base/safe_alloc.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAKEN_TEXT_MAX (4u * 1024u * 1024u)
#define TAKEN_SPAWN_MS 5000

static void taken_why(char *why, size_t cap, const char *text)
{
    if (why && cap)
        (void)snprintf(why, cap, "%s", text);
}

/* The fixture file's bytes, NUL-terminated, or NULL with why set. */
static char *taken_read_fixture(const char *path, char *why, size_t cap)
{
    FILE *fp = fopen(path, "rb");
    char *buf;
    size_t got;
    if (!fp) {
        taken_why(why, cap, "cannot read the worktree list file");
        return NULL;
    }
    buf = zcl_malloc(TAKEN_TEXT_MAX + 1u, "fleet_objectives_taken");
    if (!buf) {
        (void)fclose(fp);
        taken_why(why, cap, "out of memory reading the worktree list");
        return NULL;
    }
    got = fread(buf, 1, TAKEN_TEXT_MAX + 1u, fp);
    if (ferror(fp) || got > TAKEN_TEXT_MAX) {
        free(buf);
        (void)fclose(fp);
        taken_why(why, cap, "the worktree list file is unreadable or over the cap");
        return NULL;
    }
    (void)fclose(fp);
    buf[got] = '\0';
    return buf;
}

static char *taken_read_git(const char *repo, char *why, size_t cap)
{
    const char *argv[] = {"git", "-C", repo, "worktree", "list", "--porcelain",
                          NULL};
    struct zcl_spawn_binary_observation seen;
    char *buf = zcl_malloc(TAKEN_TEXT_MAX + 1u, "fleet_objectives_taken");
    if (!buf) {
        taken_why(why, cap, "out of memory reading the worktree list");
        return NULL;
    }
    memset(&seen, 0, sizeof(seen));
    struct zcl_result result = zcl_spawn_capture_binary(
        argv, buf, TAKEN_TEXT_MAX, TAKEN_SPAWN_MS, &seen);
    if (!result.ok || !seen.eof || seen.overflow || !seen.exit_observed ||
        seen.exit_code != 0) {
        free(buf);
        taken_why(why, cap, "git worktree list did not answer");
        return NULL;
    }
    buf[seen.output_len] = '\0';
    return buf;
}

char *zcl_objectives_worktree_text(const char *repo, const char *fixture,
                                   char *why, size_t why_cap)
{
    taken_why(why, why_cap, "");
    if (fixture && fixture[0])
        return taken_read_fixture(fixture, why, why_cap);
    return taken_read_git(repo && repo[0] ? repo : ".", why, why_cap);
}

/* `name` equals card, or starts with card then '-'. */
static bool taken_matches(const char *name, size_t len, const char *card)
{
    size_t n = strlen(card);
    if (len < n || strncmp(name, card, n) != 0)
        return false;
    return len == n || name[n] == '-';
}

/* The last path component of [text, text+len), trailing slashes ignored. */
static const char *taken_last(const char *text, size_t *len)
{
    const char *end = text + *len, *at;
    while (end > text && end[-1] == '/')
        end--;
    at = end;
    while (at > text && at[-1] != '/')
        at--;
    *len = (size_t)(end - at);
    return at;
}

/* One porcelain line: a directory or a branch that names the card. */
static bool taken_line(const char *line, size_t len, const char *card)
{
    static const char k_dir[] = "worktree ", k_branch[] = "branch refs/heads/";
    const char *name;
    size_t n;
    if (len > sizeof(k_dir) - 1 && strncmp(line, k_dir, sizeof(k_dir) - 1) == 0) {
        n = len - (sizeof(k_dir) - 1);
        name = taken_last(line + sizeof(k_dir) - 1, &n);
        return taken_matches(name, n, card);
    }
    if (len > sizeof(k_branch) - 1 &&
        strncmp(line, k_branch, sizeof(k_branch) - 1) == 0) {
        n = len - (sizeof(k_branch) - 1);
        name = line + sizeof(k_branch) - 1;
        if (taken_matches(name, n, card))
            return true;
        name = taken_last(name, &n);
        return taken_matches(name, n, card);
    }
    return false;
}

bool zcl_objectives_card_taken(const char *text, const char *card)
{
    const char *at = text;
    if (!text || !card || !card[0])
        return false;
    while (*at) {
        size_t len = strcspn(at, "\n");
        if (taken_line(at, len, card))
            return true;
        at += len;
        if (*at == '\n')
            at++;
    }
    return false;
}
