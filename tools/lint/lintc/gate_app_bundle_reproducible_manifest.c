/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: manifest half of the check-app-bundle-reproducible gate family.
 * Walks a bundle tree and renders the three manifests the proof compares:
 * path-sorted SHA-256 of every regular file, sorted "mtime mode path" lines,
 * and the sorted directory list; compares two manifests with diff -u and
 * names every differing entry; plus the small byte-exact file helpers.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "base/hex.h"
#include "gate_app_bundle_reproducible_priv.h"

enum { ABR_CHUNK = 65536 };

void abr_text_free(struct abr_text *t)
{
    free(t->p);
    *t = (struct abr_text){ 0 };
}

int abr_text_addf(struct abr_text *t, const char *fmt, ...)
{
    va_list ap, cp;
    va_start(ap, fmt);
    va_copy(cp, ap);
    int n = vsnprintf(NULL, 0, fmt, cp);
    va_end(cp);
    if (n < 0 || t->n + (size_t)n + 1 > t->cap) {
        size_t cap = t->cap ? t->cap * 2 : 4096;
        while (n >= 0 && cap < t->n + (size_t)n + 1)
            cap *= 2;
        char *p = n >= 0 ? realloc(t->p, cap) : NULL; // raw-alloc-ok:lint-runtime
        if (!p) {
            va_end(ap);
            return abr_fatal("out of memory");
        }
        t->p = p;
        t->cap = cap;
    }
    vsnprintf(t->p + t->n, (size_t)n + 1, fmt, ap);
    va_end(ap);
    t->n += (size_t)n;
    return ABR_OK;
}

static int abr_list_add(struct abr_list *l, const char *s)
{
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 64;
        char **v = realloc(l->v, cap * sizeof *v); // raw-alloc-ok:lint-runtime
        if (!v)
            return abr_fatal("out of memory");
        l->v = v;
        l->cap = cap;
    }
    char *d = strdup(s);
    if (!d)
        return abr_fatal("out of memory");
    l->v[l->n++] = d;
    return ABR_OK;
}

static void abr_list_free(struct abr_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    *l = (struct abr_list){ 0 };
}

static void abr_list_sort(struct abr_list *l)
{
    if (l->n > 1)
        qsort(l->v, l->n, sizeof *l->v, lintc_strcmp_ptr);
}

/* "./a/b" relative to root -> root/a/b ("." -> root). */
static int abr_abs(char *out, const char *root, const char *rel)
{
    return rel[1] == '\0' ? abr_pathf(out, "%s", root) : abr_pathf(out, "%s/%s", root, rel + 2);
}

static int abr_walk_entry(const char *root, const char *rel, const char *name,
                          struct abr_list *files, struct abr_list *dirs, int depth);

#ifdef ZCL_TESTING
struct abr_seam abr_seam;

/* Counts directory handles and injects enumeration faults for the selftest. */
static DIR *abr_opendir(const char *path)
{
    DIR *d = opendir(path);
    abr_seam.opened += d != NULL;
    return d;
}

static void abr_closedir(DIR *d)
{
    abr_seam.closed++;
    closedir(d);
}

static struct dirent *abr_readdir(DIR *d)
{
    struct dirent *e = readdir(d);
    long n = ++abr_seam.reads;
    if (n == abr_seam.fail_at) {
        errno = EIO;
        return NULL;
    }
    if (n == abr_seam.dirty_at)
        errno = ENOENT;
    return e;
}
#else
#define abr_opendir opendir
#define abr_closedir closedir
#define abr_readdir readdir
#endif

/* Reads every entry of d; a NULL readdir with errno set is an enumeration
 * failure, never the end of the directory. */
static int abr_walk_dir(DIR *d, const char *dir, const char *root, const char *rel,
                        struct abr_list *files, struct abr_list *dirs, int depth)
{
    int rc = ABR_OK;
    while (!rc) {
        errno = 0;
        struct dirent *e = abr_readdir(d);
        if (!e)
            return errno ? abr_fatal("cannot enumerate directory %s", dir) : ABR_OK;
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            rc = abr_walk_entry(root, rel, e->d_name, files, dirs, depth);
    }
    return rc;
}

/* Collects regular files and directories below rel, find(1) style: symbolic
 * links are neither followed nor listed. */
static int abr_walk(const char *root, const char *rel, struct abr_list *files,
                    struct abr_list *dirs, int depth)
{
    char dir[ABR_PATH];
    int rc = abr_abs(dir, root, rel);
    if (rc)
        return rc;
    if (depth > ABR_DEPTH)
        return abr_fatal("directory nesting too deep at %s", dir);
    DIR *d = abr_opendir(dir);
    if (!d)
        return abr_fatal("cannot read directory %s", dir);
    rc = abr_walk_dir(d, dir, root, rel, files, dirs, depth);
    abr_closedir(d);
    return rc;
}

static int abr_walk_entry(const char *root, const char *rel, const char *name,
                          struct abr_list *files, struct abr_list *dirs, int depth)
{
    char child[ABR_PATH], path[ABR_PATH];
    struct stat st;
    int rc = abr_pathf(child, "%s/%s", rel, name);
    if (rc || (rc = abr_abs(path, root, child)))
        return rc;
    if (lstat(path, &st) != 0)
        return abr_fatal("cannot stat %s", path);
    if (S_ISREG(st.st_mode))
        return abr_list_add(files, child);
    if (!S_ISDIR(st.st_mode))
        return ABR_OK;
    if ((rc = abr_list_add(dirs, child)))
        return rc;
    return abr_walk(root, child, files, dirs, depth + 1);
}

static int abr_hash_file(const char *path, char hex[ZSHA256_HEX_LEN])
{
    static unsigned char buf[ABR_CHUNK];
    uint8_t digest[ZSHA256_DIGEST_LEN];
    zsha256_ctx ctx;
    ssize_t n;
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return abr_fatal("cannot open %s", path);
    zsha256_init(&ctx);
    while ((n = read(fd, buf, sizeof buf)) > 0)
        zsha256_update(&ctx, buf, (size_t)n);
    close(fd);
    if (n < 0)
        return abr_fatal("cannot read %s", path);
    zsha256_final(&ctx, digest);
    zcl_hex_encode(digest, sizeof digest, hex);
    return ABR_OK;
}

/* ls -l style: "-rwxr-xr-x", with s/S and t/T for the special bits. */
void abr_mode_string(unsigned mode, char out[11])
{
    static const char rwx[] = "rwxrwxrwx";
    for (int i = 0; i < 9; i++)
        out[i + 1] = (mode & (0400u >> i)) ? rwx[i] : '-';
    if (mode & S_ISUID)
        out[3] = (mode & 0100u) ? 's' : 'S';
    if (mode & S_ISGID)
        out[6] = (mode & 0010u) ? 's' : 'S';
    if (mode & 01000u)
        out[9] = (mode & 0001u) ? 't' : 'T';
    out[0] = '-';
    out[10] = '\0';
}

static int abr_meta_lines(const char *root, const struct abr_list *files, struct abr_list *meta)
{
    char path[ABR_PATH], mode[11], line[ABR_PATH + 64];
    struct stat st;
    for (size_t i = 0; i < files->n; i++) {
        int rc = abr_abs(path, root, files->v[i]);
        if (rc)
            return rc;
        if (lstat(path, &st) != 0)
            return abr_fatal("cannot stat %s", path);
        abr_mode_string((unsigned)st.st_mode, mode);
        if (snprintf(line, sizeof line, "%lld %s %s", (long long)st.st_mtime, mode,
                     files->v[i]) >= (int)sizeof line)
            return abr_fatal("path too long");
        if ((rc = abr_list_add(meta, line)))
            return rc;
    }
    return ABR_OK;
}

static int abr_content_lines(const char *root, const struct abr_list *files, struct abr_text *out)
{
    char path[ABR_PATH], hex[ZSHA256_HEX_LEN];
    for (size_t i = 0; i < files->n; i++) {
        int rc = abr_abs(path, root, files->v[i]);
        if (rc || (rc = abr_hash_file(path, hex)) || (rc = abr_text_addf(out, "%s  %s\n", hex, files->v[i])))
            return rc;
    }
    return ABR_OK;
}

static int abr_join_lines(const struct abr_list *l, struct abr_text *out)
{
    for (size_t i = 0; i < l->n; i++) {
        int rc = abr_text_addf(out, "%s\n", l->v[i]);
        if (rc)
            return rc;
    }
    return ABR_OK;
}

int abr_write_file(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return abr_fatal("cannot write %s", path);
    if (fwrite(data, 1, len, f) != len || fclose(f) != 0)
        return abr_fatal("cannot write %s", path);
    return ABR_OK;
}

/* path-sorted "sha256  path" lines for every regular file under root. */
int abr_content_manifest(const char *root, struct abr_text *out)
{
    struct abr_list files = { 0 }, dirs = { 0 };
    int rc = abr_walk(root, ".", &files, &dirs, 0);
    if (!rc) {
        abr_list_sort(&files);
        rc = abr_content_lines(root, &files, out);
    }
    abr_list_free(&files);
    abr_list_free(&dirs);
    return rc;
}

static int abr_emit(const char *tmp, const char *kind, const char *tag, const struct abr_text *t)
{
    char path[ABR_PATH];
    int rc = abr_pathf(path, "%s/%s.%s", tmp, kind, tag);
    return rc ? rc : abr_write_file(path, t->p ? t->p : "", t->n);
}

/* Writes tmp/content.TAG, meta.TAG and shape.TAG for the tree at root;
 * reports the content line count and the SHA-256 of the content manifest. */
int abr_manifest_tree(const char *root, const char *tmp, const char *tag, int *lines,
                      char sha[ZSHA256_HEX_LEN])
{
    struct abr_list files = { 0 }, dirs = { 0 }, meta = { 0 };
    struct abr_text content = { 0 }, mt = { 0 }, shape = { 0 };
    int rc = abr_list_add(&dirs, ".") ? ABR_FATAL : abr_walk(root, ".", &files, &dirs, 0);
    if (!rc) {
        abr_list_sort(&files);
        abr_list_sort(&dirs);
        rc = abr_content_lines(root, &files, &content);
    }
    if (!rc && !(rc = abr_meta_lines(root, &files, &meta))) {
        abr_list_sort(&meta);
        rc = abr_join_lines(&meta, &mt) ? ABR_FATAL : abr_join_lines(&dirs, &shape);
    }
    if (!rc && !(rc = abr_emit(tmp, "content", tag, &content)) && !(rc = abr_emit(tmp, "meta", tag, &mt)))
        rc = abr_emit(tmp, "shape", tag, &shape);
    if (!rc) {
        uint8_t d[ZSHA256_DIGEST_LEN];
        zsha256(content.p ? content.p : "", content.n, d);
        zcl_hex_encode(d, sizeof d, sha);
        *lines = (int)files.n;
    }
    abr_list_free(&files);
    abr_list_free(&dirs);
    abr_list_free(&meta);
    abr_text_free(&content);
    abr_text_free(&mt);
    abr_text_free(&shape);
    return rc;
}

/* Last whitespace-separated field of a diff line, like awk's $NF. */
static char *abr_last_field(char *line)
{
    size_t n = strlen(line);
    while (n && (line[n - 1] == ' ' || line[n - 1] == '\t'))
        line[--n] = '\0';
    while (n && line[n - 1] != ' ' && line[n - 1] != '\t')
        n--;
    return line + n;
}

static int abr_changed_entries(const char *diff, struct abr_list *out)
{
    char *copy = strdup(diff), *save = NULL;
    if (!copy)
        return abr_fatal("out of memory");
    int rc = ABR_OK;
    for (char *l = strtok_r(copy, "\n", &save); l && !rc; l = strtok_r(NULL, "\n", &save)) {
        if ((l[0] == '+' || l[0] == '-') && l[1] && l[1] != '+' && l[1] != '-')
            rc = abr_list_add(out, abr_last_field(l));
    }
    free(copy);
    return rc;
}

static void abr_print_diff(FILE *err, const char *label, const char *diff)
{
    struct abr_list ent = { 0 };
    abr_note(err, "FAIL — %s differs between the two bundle runs.", label);
    fputs("  Differing entries:\n", err);
    if (abr_changed_entries(diff, &ent) == ABR_OK) {
        abr_list_sort(&ent);
        for (size_t i = 0; i < ent.n; i++) {
            if (i == 0 || strcmp(ent.v[i], ent.v[i - 1]) != 0)
                fprintf(err, "    %s\n", ent.v[i]);
        }
    }
    abr_list_free(&ent);
    fputs("  Full diff:\n", err);
    for (const char *p = diff; *p;) {
        size_t n = strcspn(p, "\n");
        fprintf(err, "    %.*s\n", (int)n, p);
        p += n + (p[n] == '\n');
    }
}

/* ABR_OK when the two manifest files are identical, ABR_FAIL after naming
 * every differing entry on err (NULL silences it). */
int abr_compare(const char *label, const char *a, const char *b, FILE *err)
{
    char *const argv[] = { (char *)"diff", (char *)"-u", (char *)a, (char *)b, NULL };
    struct lcp_buf out = { 0 };
    int code, rc = abr_exec(argv, LCP_BOTH, NULL, &out, &code);
    if (rc == ABR_OK && code != 0) {
        if (err)
            abr_print_diff(err, label, out.data ? out.data : "");
        rc = ABR_FAIL;
    }
    lcp_buf_free(&out);
    return rc;
}

static int abr_slurp(const char *path, struct abr_text *t)
{
    static char buf[ABR_CHUNK];
    ssize_t n;
    int fd = open(path, O_RDONLY), rc = ABR_OK;
    if (fd < 0)
        return abr_fatal("cannot open %s", path);
    while (!rc && (n = read(fd, buf, sizeof buf)) > 0) {
        char *p = realloc(t->p, t->n + (size_t)n + 1); // raw-alloc-ok:lint-runtime
        if (!p) {
            rc = abr_fatal("out of memory");
            break;
        }
        memcpy(p + t->n, buf, (size_t)n);
        t->p = p;
        t->n += (size_t)n;
    }
    if (!rc && n < 0)
        rc = abr_fatal("cannot read %s", path);
    close(fd);
    return rc;
}

/* ABR_OK when both files hold the same bytes, ABR_FAIL when they differ. */
int abr_same_file(const char *a, const char *b)
{
    struct abr_text x = { 0 }, y = { 0 };
    int rc = abr_slurp(a, &x);
    if (!rc && !(rc = abr_slurp(b, &y)))
        rc = x.n == y.n && (x.n == 0 || memcmp(x.p, y.p, x.n) == 0) ? ABR_OK : ABR_FAIL;
    abr_text_free(&x);
    abr_text_free(&y);
    return rc;
}

int abr_copy_file(const char *from, const char *to)
{
    struct abr_text t = { 0 };
    int rc = abr_slurp(from, &t);
    if (!rc)
        rc = abr_write_file(to, t.p ? t.p : "", t.n);
    abr_text_free(&t);
    return rc;
}
