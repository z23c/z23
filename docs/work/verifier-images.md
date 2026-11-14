# Fixed-result verifier images and seccomp filter

Status: DESIGN, built and tested without root. Nothing here is installed.
Installing it is a root step that needs its own operator grant (see
[`separate-verifier.md`](./separate-verifier.md), "Privileged installation
packet"). The byte contract that consumes these roots is
[`verifier-contract-v2.md`](./verifier-contract-v2.md).

The launcher (`tools/verify/fixed_result_launcher.c`) checks three image
trees and one filter file against pins v2 before every launch:

| Pin | Installed path | Produced by |
|---|---|---|
| `source_image_sha3`, `source_content_sha3` | `/var/lib/z23verify/images/fixed_result/source` | `z23-fixed-result-image source` |
| `tool_image_sha3` | `/var/lib/z23verify/images/fixed_result/tool` | `z23-fixed-result-image tool` |
| `check_image_sha3` | `/var/lib/z23verify/images/fixed_result/check` | `z23-fixed-result-image check` |
| `seccomp_filter_sha3` | `/etc/z23verify/fixed_result.seccomp.bpf` | `z23-fixed-result-seccomp emit` |

Each image root is the `tree_sha3` that `z23-tree-closure hash DIR 0`
prints for the root-owned tree. The builder prints that value in advance as
`root_tree_sha3` (the same walk, hashing UID 0 in place of the builder's
UID), so a developer build predicts the root that root's build must match.
Every output line ends `attest_eligible=0`: a printed root is an input for
review and for the pins file, not evidence.

## Image format

- Root layout. Every input sits at its own absolute path. Directories are
  0755. Files are 0555 if the host file had any execute bit, otherwise 0444.
  Symlinks are kept. An absolute target is rewritten to the equivalent
  relative one, so it resolves inside the image when the image is `/`.
- Entries are sorted and hashed by `tools/verify/tree_closure.c`. The builder
  links that file in, so the image and the launcher preflight use the same
  code.
- The manifest (`z23verify.fixed_result.image.v1`) lists every `D`, `F` and
  `L` entry with its mode, size and SHA3-256. It ends with the counts and the
  three roots.
- The builder refuses, naming the path:
  - `input_missing`, `input_unreadable`, `input_special` (FIFO, socket or
    device), `input_symlink_escapes` (a link that climbs above `/`),
    `input_symlink_loop`;
  - `input_changed` (a host file changed between the copy and the final
    re-hash);
  - `input_pin_mismatch` (a source file is not the pinned bytes);
  - `image_extra_entry` / `image_changed` (the tree gained an entry or
    changed after the copy);
  - `elf_search_path_unsupported` (RPATH/RUNPATH), `elf_needed_missing`.

### Source image

This image holds three files, each checked against its pin before it is
copied:

- `platform/modules/base/src/result.c` (SHA3 `f8a4357f…`);
- `platform/modules/base/include/base/result.h` (`e92c831f…`);
- `platform/modules/base/include/base/format_attribute.h` (`1667ffb4…`).

It also holds every `-I` directory the pinned profile names, created empty.
With the directories present, a header newly placed anywhere on the search
path changes the content root. The source content root is owner-independent,
so the receiver can rebuild it from its own tree.

### Tool image

The image is discovered from the exact worker compile. That is the profile
`tools/verify/fixed_result_fast.args` (SHA3 checked, `@CWD@` expanded once)
plus the worker's tail `-MMD -MP -MF … -MT <target> -E|-c -o … result.c`.
It is run in both modes (`-E` with `-fno-working-directory`, and `-c`) under
`LC_ALL=C TZ=UTC TMPDIR=/tmp PATH=/usr/bin:/bin`. Discovery runs twice:

1. **Traced.** `strace -f -ff` over both compiles records every path each
   process found and every path it probed and missed.
2. **Static.** The builder walks the driver's own answers:
   `-print-prog-name=cc1` and `as`, `-print-file-name=specs`, the `-E -v`
   include list and the `-M` dependency list. Then it follows the ELF
   `PT_INTERP` and `DT_NEEDED` closure of every program.

The image is the union of both walks, plus:

- the mount points the jail binds (`proc`, `tmp`, `work`, `zclassic23`,
  `dev/null`, `usr/local/libexec/z23-fixed-result-worker`);
- the pinned profile at `etc/z23verify/fixed_result_fast.args`.

Any path the traced compile probed and missed must be absent in the image.
On this host the two walks agree exactly. `trace_only=0`, and
`static_only=1`, the ELF interpreter, which the kernel maps without an
`open`. The `--static` build and the traced build give the same root. No
`specs` file exists, so GCC uses its built-in specs. A `specs` file placed
later changes the root.

### Check image

`check --out DIR NAME=/abs/path…` places each executable at
`/usr/local/libexec/NAME` (0555) with its loader closure. `NAME` must be a
plain name. The contract does not yet fix which checker programs belong
there. The natural first member is
`z23-tree-closure=/usr/local/libexec/z23-tree-closure`, so its root is
pinned once the reviewer fixes that list.

## Pin values on this host (GCC 14.2, Ubuntu 24.04 x86-64)

| Value | SHA3-256 |
|---|---|
| `source_content_sha3` | `0011536cd9c35eb545c5fa6a5c9c16aa91aa7d55a1a6a9f398c4e8dfa50f5fcf` |
| `source_image_sha3` (root-owned) | `4f50734a2a31b17d7d17457f6fc235efd4424c44f0d645fe3b9bb282e906d0ad` |
| tool image `content_sha3` | `303d7c9f2b16fb84f361ade4259c3d58e9d7f169aee5c93bdf0073a95f09c433` |
| `tool_image_sha3` (root-owned) | `dbd4310d7e5e2620476eba00312307c3f27a93abbf1af9bbbf1e190080604904` |
| `seccomp_filter_sha3` | `6e764681d4ca638819faa76db1d9dcc1c520c34c70a6f73661d9a01a6c3482ec` |
| result.o from the image | `fc32be7b826288a379948dc040b15f60ebf50c68167689bad7e72fb23908322a` (4,496 bytes) |

- The source image has 325 entries (3 files, 321 directories) and 8,350
  bytes.
- The tool image has 97 entries (50 files, 16 links, 30 directories) and
  45,528,346 bytes.
- `toolchain_id` is `z23.gcc14.fast_result.v2:` followed by the tool image
  root.
- The source pins change only with the three pinned files or the profile.
  The tool pin changes with any package update to GCC, binutils or their
  libraries. Rebuild and re-review it after every such update; never edit a
  pin to match.
- A driver other than GCC 14.2 on Ubuntu 24.04 emits its own cold result.o.
  The no-root proof still requires the tool image to reproduce that object
  byte for byte. These pinned result.o bytes are required when the object
  is 4,496 bytes.

## No-root completeness proof

`z23-fixed-result-image prove --tool DIR --repo R --profile P --scratch S`
compiles the pinned argv twice from a fresh source image:

- once with the host `/usr/bin/cc` (the cold reference);
- once entirely from the tool image. That run goes through the image's own
  `ld-linux-x86-64.so.2` with `--inhibit-cache` and an image-only
  `--library-path`. It uses `-wrapper` so cc1 and as load the same way, sets
  `GCC_EXEC_PREFIX`, `COMPILER_PATH` and `--sysroot` to the image, and adds
  `-ffile-prefix-map=<image>=` so the DWARF strings match.

The image run is traced. Every path it touched is classified as image,
snapshot, scratch, `/tmp`, `/dev/null`, `/proc/self`, the loader cache, an
ancestor directory, or outside. Measured result:

- The object is byte-identical to the cold compile (`268e7e07…`). The
  dependency file and stderr are identical too.
- 230 image reads and `leaks=0`.
- Two absent paths outside the image were probed:
  - `/etc/ld.so.preload`, by the loader;
  - `/usr/lib/gcc/x86_64-linux-gnu/specs`, by the driver's fixed specs
    probe.

  Both are absent on the host and absent in the image. In the jail the image
  is `/`, so both resolve inside it.
- `/etc/ld.so.cache` is excluded by design. The image run inhibits it and
  the jail's loader finds its libraries in the default directories.
- Equivalence check: the host run found 82 tool paths and missed 109. The
  image presents every one it found and hides every one it missed, with
  `mismatches=0`.

This proof does not show the jail itself. It shows that the image is
sufficient and that the compile's view of it equals the host's view. The
mount namespace, the separate UID and the seccomp filter are proved only by
the installed launcher.

## Seccomp filter

`tools/verify/fixed_result_seccomp.c` emits 95 classic-BPF instructions
(760 bytes, little-endian `sock_filter`), in this order:

1. A non-x86-64 `arch` is `KILL_PROCESS`, as is an x32 syscall number.
2. A fixed allowlist of the calls GCC 14's driver, cc1 and as make.
3. Everything else is `ERRNO(EPERM)`.

Some allowlisted calls have argument rules:

- `clone` is allowed only without namespace flags.
- `clone3` gets `ENOSYS`, so glibc falls back to `clone`.
- `ioctl` is `TCGETS` only.
- `prctl` is `PR_GET_NO_NEW_PRIVS` and `PR_GET_SECCOMP` only.

`z23-fixed-result-seccomp print` lists the policy and the pin. `verify FILE`
checks installed bytes against it.

Tested without root:

- The kernel installs the filter with `no_new_privs`, and
  `PR_GET_SECCOMP` reads 2.
- These calls all return `EPERM`: `socket` (INET and UNIX), `ptrace`,
  `unshare(CLONE_NEWUSER)`, `clone(CLONE_NEWUSER)`, `setns`, `personality`,
  `memfd_create` and `mount`. Without the filter, `socket`, `ptrace`,
  `setns(-1)`, `personality` and `memfd_create` succeed or fail with another
  errno, so their `EPERM` is the filter's. Unprivileged `mount` and user
  namespaces can be `EPERM` anyway on this host.
- The reference evaluator checks the calls glibc does not wrap (`bpf`,
  `io_uring_*`, `keyctl`, `userfaultfd`, `perf_event_open` and others), plus
  foreign-arch and x32 `KILL_PROCESS`, against the same bytes.
- `gcc -c result.c` under the filter produces `268e7e07…`.

## Root commands

Build the two CLIs from the reviewed, signed commit, as that commit's
checkout. The owner compares the binaries' SHA3 before use:

```sh
cc -std=c23 -O2 -Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200809L \
  -DZCL_TREE_CLOSURE_NO_MAIN -Itools -Itools/verify \
  -Iplatform/modules/sha3/include -Iplatform/modules/base/include \
  tools/verify/fixed_result_image_main.c tools/verify/fixed_result_image.c \
  tools/verify/fixed_result_image_elf.c tools/verify/fixed_result_image_run.c \
  tools/verify/fixed_result_image_build.c tools/verify/fixed_result_image_proof.c \
  tools/verify/tree_closure.c platform/modules/sha3/src/sha3.c \
  platform/modules/base/src/safe_alloc.c -o z23-fixed-result-image
cc -std=c23 -O2 -Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200809L \
  -Itools -Itools/verify -Iplatform/modules/sha3/include \
  -Iplatform/modules/base/include tools/verify/fixed_result_seccomp_main.c \
  tools/verify/fixed_result_seccomp.c platform/modules/sha3/src/sha3.c \
  -o z23-fixed-result-seccomp
```

Then, as root, with `R` the reviewed checkout and the three image
directories absent:

```sh
install -d -o root -g root -m 0755 /var/lib/z23verify/images/fixed_result /etc/z23verify
install -d -o root -g root -m 0700 /root/z23verify-scratch
P=R/tools/verify/fixed_result_fast.args
./z23-fixed-result-image source --repo R --profile "$P" \
  --out /var/lib/z23verify/images/fixed_result/source   > source.manifest
./z23-fixed-result-image tool --repo R --profile "$P" --scratch /root/z23verify-scratch \
  --out /var/lib/z23verify/images/fixed_result/tool     > tool.manifest
./z23-fixed-result-image check \
  --out /var/lib/z23verify/images/fixed_result/check \
  z23-tree-closure=/usr/local/libexec/z23-tree-closure  > check.manifest
./z23-fixed-result-seccomp emit > /etc/z23verify/fixed_result.seccomp.bpf
chmod 0444 /etc/z23verify/fixed_result.seccomp.bpf
./z23-fixed-result-seccomp verify /etc/z23verify/fixed_result.seccomp.bpf
for d in source tool check; do
  /usr/local/libexec/z23-tree-closure hash /var/lib/z23verify/images/fixed_result/$d 0
done
```

Accept only if all of the following hold:

- Each `z23-tree-closure` `tree_sha3` equals that manifest's
  `root_tree_sha3` and `pin …_image_sha3` line.
- The source and tool values equal the table above, or a re-reviewed
  replacement for a changed GCC.
- Each summary line reads `ancestors_checked=1` (under euid 0 the builder
  refuses an output whose parent chain fails the `z23-tree-closure`
  ancestor rule for UID 0).
- `verify` prints `fixed_result_seccomp_verified=1` (the file equals the
  generated bytes) and `print` shows the pinned `seccomp_filter_sha3`.

`--scratch` must lie outside the tool image; the build refuses one inside
it. Delete it after the build.

## Open findings for the jail

- The worker reads `/proc/self/status`. The launch policy's `mounts=` list
  names no `/proc`, so the jail needs a `proc` mount (the image carries the
  mount point) or the worker must stop reading it.
- The jail must bind the worker at
  `/usr/local/libexec/z23-fixed-result-worker`. The tool image carries an
  empty 0555 file there as the mount point, and that file is part of the
  tool root.
- The filter is built for GCC 14 on glibc 2.39. A toolchain update that
  needs a new syscall shows up as a compile failure under the filter (the
  kernel test above), never as a silent allow.
