# zwalk

Bounded recursive directory traversal for C23 — deterministic order,
explicit depth bound, fail-closed on filesystem errors. Leaf package:
libc (`dirent`/`stat`) only, no dependencies.

## Design

- **Deterministic order.** Entries within each directory are sorted by
  byte-wise name comparison before visiting (`readdir` order is
  unspecified), so a walk is reproducible across runs, filesystems, and
  machines. Walk output may be diffed.
- **Symlinks are never followed by default.** Following links turns a
  tree walk into a graph walk: cycles, escaped subtrees, surprising
  duplicate work. With the default `follow_symlinks=false` a symlink is
  reported once as `ZWALK_SYMLINK` and never descended. Opting in with
  `follow_symlinks=true` is documented as dangerous: `max_depth` is the
  only cycle guard, and a dangling link fails the walk.
- **Bounded.** Recursion is capped at `max_depth` (default 32), joined
  paths at `PATH_MAX` bytes, directory fan-out at `ZWALK_MAX_ENTRIES`
  (2^20) per directory.
- **Fail-closed.** An unreadable directory, a failed stat, an over-long
  path, or fan-out over the cap aborts the walk and returns false —
  never silent omission.

## API summary

```c
struct zwalk_opts {
  int max_depth;        /* deepest level visited; 0 = root only */
  bool skip_hidden;     /* skip names starting with '.' */
  bool follow_symlinks; /* DANGER: see above; default false */
};

typedef zwalk_action (*zwalk_visit_fn)(void *ctx, const char *path,
                                       zwalk_type type, int depth,
                                       uint64_t size);

bool zwalk(const char *root, const struct zwalk_opts *opts,
           zwalk_visit_fn visit, void *ctx);
```

Visit contract: the root is visited first at depth 0, children at
depth 1 up to `max_depth`. `size` is the byte size for `ZWALK_FILE`,
0 for other types. The callback returns `ZWALK_GO` to continue,
`ZWALK_SKIP` to prune a directory's children, or `ZWALK_STOP` to end
the walk early (`zwalk` still returns true). `path` is valid only
during the callback. The root may itself be a plain file.

## Example

```c
static zwalk_action count(void *ctx, const char *p, zwalk_type t,
                          int depth, uint64_t size) {
  (void)p; (void)depth;
  if (t == ZWALK_FILE) *(uint64_t *)ctx += size;
  return ZWALK_GO;
}
uint64_t bytes = 0;
zwalk("/srv/data", NULL, count, &bytes); /* NULL opts = defaults */
```

## App

`app/main.c` builds a tiny find: `zwalk [-L] [-H] [-d N] DIR` prints the
tree with two-space indent, file sizes, and symlink markers in
deterministic order; exit 0 on success, 2 on misuse, 1 on walk failure.

## Tests

`tests/test_zwalk.c` builds its own fixture tree under a relative
directory in the current working directory (sandbox-friendly: no /tmp,
no TMPDIR)
(regular files with known sizes, nested directories, an empty directory,
a dotfile, a file symlink, and a directory symlink) and verifies the
exact sorted visit sequence, the depth limit at 0 and 1, `skip_hidden`,
symlink reporting by default vs. resolution and descent with
`follow_symlinks=true`, `ZWALK_SKIP` pruning, `ZWALK_STOP` early exit,
file-as-root, and fail-closed rejection of NULL/empty/nonexistent roots
and negative depth.
