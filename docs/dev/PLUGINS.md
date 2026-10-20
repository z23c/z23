<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Signed plugin store

`z23 plugin` keeps plugin executables under `~/.z23/plugins`. A plugin is
installed only when its manifest is strictly formed, its detached Ed25519
signature verifies against a key listed in `publisher_keys`, and the executable
matches the SHA3-512 in the signed manifest. The daemon is not involved: these
commands read and write files only.

## Layout

```text
~/.z23/plugins/
  publisher_keys                      one public key per line
  NAME/
    generations/<SHA3-512 hex>/
      NAME                          executable, mode 0555 on POSIX
      NAME.plugin.json              manifest, mode 0444 on POSIX
      NAME.plugin.sig               signature, mode 0444 on POSIX
    current    -> generations/<id>  symbolic link on POSIX
    last-good  -> generations/<id>  symbolic link on POSIX
```

The generation id is the SHA3-512 of the signed manifest (domain-tagged, as
signed) as 128 lowercase hex characters. It covers the capabilities and the
executable hash, so the same executable under new capabilities is a new
generation. Generations stored under the executable hash still work. Installing stores a generation and leaves `current` alone.
On POSIX, `switch` and `rollback` replace the links by creating a temporary
symbolic link beside them and renaming it over the old one, so a reader sees
the old or the new target and never a missing link. An interrupted swap leaves
`current` unchanged; the next swap removes the leftover temporary link.

On Windows, `current` and `last-good` are ordinary private files, opened and
validated through the retained directory capability. Each contains exactly
141 bytes: `generations/`, 128 lowercase hex characters, then one LF byte,
with no NUL or extra bytes. A flushed temporary file is atomically published
over the old pointer. Reparse points and malformed pointer files are refused.
If a namespace move completes but its final identity or durability proof
fails, the operation reports `PLUGIN_IO` and preserves the involved files
for reconciliation; an error alone does not prove that the move did not occur.

## Permissions

On POSIX, `publisher_keys` must be a regular file owned by you and not writable
by group or others. `~/.z23/plugins`, each `NAME` directory and each
`generations` directory must be real directories with the same ownership and
mode rule. Nothing inside the store may be a symbolic link except `current`
and `last-good`, whose targets must have the form `generations/<128 hex>`.
A violation is refused with `PLUGIN_KEYS_INSECURE`.

On Windows, the store directories, `publisher_keys`, signing keys and generation
pointer files use protected ACLs owned by the current account, granting full
access only to that account and SYSTEM, with no inherited or additional ACEs.
Signing keys and `publisher_keys` also require an existing owner-private parent
directory with this ACL. An existing pack output directory must be private;
a new output directory is created private. Reparse points are refused.
Insecure signing keys or key parents report `PLUGIN_KEY_INSECURE`; insecure
publisher key files or store directories report `PLUGIN_KEYS_INSECURE`.

Windows storage operations do not enable plugin execution or establish a
confinement guarantee. `plugin run` remains Linux-only and refuses other hosts
with `PLUGIN_RUN_PLATFORM`.

## Manifest

`NAME.plugin.json` must contain exactly these keys. An unknown or repeated key
is refused.

```json
{
  "schema": "z23.plugin.v1",
  "name": "hello",
  "version": "1.0.0",
  "interface_version": 1,
  "sha3_512": "<128 lowercase hex: SHA3-512 of the executable>",
  "capabilities": ["fs.read", "clock"]
}
```

- `name`: 1 to 32 characters from `a-z`, `0-9`, `-`; it must match the file
  name `NAME.plugin.json`.
- `version`: 1 to 64 characters from `A-Za-z0-9.+-`.
- `interface_version`: 1 (resident daemon, run by `plugin run`) or 2 (one-shot
  program, run by `plugin call`); any other value is refused.
- `capabilities`: distinct entries from `fs.read`, `fs.write`, `net.client`,
  `net.server`, `process.spawn`, `clock`, `ui.panel`.

## Signature

`NAME.plugin.sig` is a JSON object with exactly `sig_alg`, `public_key` and
`signature`:

```json
{"sig_alg":"ed25519","public_key":"<64 hex>","signature":"<128 hex>"}
```

`sig_alg` must be `ed25519`. The signature covers the 64-byte SHA3-512 digest
of the bytes `z23.plugin.manifest.v1`, one NUL byte, and the exact bytes of
`NAME.plugin.json`. Any edit to the manifest, including whitespace, invalidates
it.

## Publishing a plugin

`z23 plugin keygen` creates a signing key and `z23 plugin pack` writes the
manifest, the detached signature and a copy of the executable that
`z23 plugin install` accepts. Neither command contacts the daemon.

```sh
z23 plugin keygen ./publisher.key
z23 plugin pack ./hello --name=hello --version=1.0.0 --key=./publisher.key \
    --cap=fs.read,clock --dir=./dist
```

`keygen` prints one result document; `data.public_key` is the line for
`publisher_keys`, and the secret is never printed:

```json
{"schema":"zcl.plugin_keygen.v1","public_key":"94da1a987b44af1793538d4c6ec4fa5f2146aa9380ad4a57f1eba3aba6d02423","key_file":"./publisher.key"}
```

`pack` creates `./dist/hello`, `./dist/hello.plugin.json` and <!-- doc-path-ok: example output path -->
`./dist/hello.plugin.sig` and reports `data` with `generation` (the signed-manifest
digest), `public_key`, `manifest` and `capabilities`. For the
example above `hello.plugin.json` is:

```json
{"schema":"z23.plugin.v1","name":"hello","version":"1.0.0","interface_version":1,"sha3_512":"7d2971759a8fd40678d0e693a6baaacbda6b8c9e98bbf5ddbd61a9eedc29af554a4e7685ae018caff0162abbd79cfaa662b31b3d7f6f4b2cae3af1b8568e3bac","capabilities":["fs.read","clock"]}
```

and `hello.plugin.sig` is:

```json
{"sig_alg":"ed25519","public_key":"94da1a987b44af1793538d4c6ec4fa5f2146aa9380ad4a57f1eba3aba6d02423","signature":"ece1ba9c0b8f3e077c91f65a837515b3dbef3524ee350a11bd134b8fe85bfb54fe827aa63c4555ed96351af7fb407c5f1e2c4f4b3620e002a0d83975ef87840b"}
```

To install it on a machine, list the key as a publisher key and install the manifest:

```sh
printf '%s\n' 94da1a987b44af1793538d4c6ec4fa5f2146aa9380ad4a57f1eba3aba6d02423 >> ~/.z23/plugins/publisher_keys
z23 plugin install ./dist/hello.plugin.json
```

- **Key file.** Exactly the 32-byte Ed25519 seed (RFC 8032), the same form as
  the onion vanity seed. `keygen` creates it exclusively from the host CSPRNG,
  with mode 0600 on POSIX or the protected Windows ACL above, and refuses an
  existing path with `PLUGIN_KEY_EXISTS`. Windows requires the owner-private
  key parent for both creation and loading. A failed durability observation
  can leave an exclusively created private key for owner reconciliation;
  `keygen` still refuses to overwrite it. `pack`
  refuses a key file that is not a regular file you own, that group or others
  can access, that is a symbolic link (`PLUGIN_KEY_INSECURE`), or whose size is
  not 32 bytes (`PLUGIN_KEY_MALFORMED`).
- **Arguments.** `--name` and `--version` follow the manifest rules above.
  `--cap` is a comma-separated list of distinct capabilities, or a JSON array
  through `--input`; it is optional. `--dir` is the output directory, created
  when missing (default: the current directory). `--interface` is 1 or 2
  (default 1).
- **Reproducible output.** The manifest lists capabilities in vocabulary order
  and Ed25519 signing is deterministic, so equal inputs give byte-identical
  files. The executable is hashed while it is copied, so the signed digest is
  that of the bytes in the output directory. Existing outputs of the same name
  are overwritten. Each of the three files is replaced atomically through a
  temporary sibling and a rename, but not as a set: a failure part way can
  leave a manifest, signature and executable that do not match, which
  `install` refuses. On POSIX, `--dir` follows a symbolic link and creates only
  the last missing path level, with mode 0700. Windows requires a real private
  output directory and refuses reparse points.
- **Signature.** The signature covers the manifest bytes exactly as written,
  ending with one newline, as described under Signature.

## Publisher keys

`~/.z23/plugins/publisher_keys` holds one full Ed25519 public key per line as 64
hex characters. Blank lines are ignored; any other line is refused. The file
must exist and name at least one key to verify a plugin. Earlier builds read the
key list from a different file name; move its lines to publisher_keys.

```sh
z23 plugin publisher <64-hex-public-key>
```

## Commands

```sh
z23 plugin install ./hello.plugin.json     # signature file and executable sit beside it
z23 plugin list
z23 plugin status hello                    # inspect one plugin without verification
z23 plugin switch hello <128-hex generation>
z23 plugin rollback hello
z23 plugin run hello [seconds]             # supervise the current generation
z23 plugin call upper --stdin=abc          # run an interface 2 plugin once
z23 plugin keygen ./publisher.key          # publisher: create a signing key
z23 plugin pack ./hello --name=hello --version=1.0.0 --key=./publisher.key
```

- `install` verifies the source files, copies them to a staging directory,
  verifies the copy again, then renames it into `generations/`. Installing a
  generation that is already stored and verifies reports `already_present` and
  changes nothing. A stored generation that fails verification is moved aside
  and replaced by the verified staged copy, so `current` never keeps pointing
  at a broken generation.
- `list` prints, for each plugin, `current`, `last_good` and every stored
  generation, plus `current_state`, `last_good_state` and `generations_state`.
  Each state is `ok`, `missing`, `unreadable` or `corrupt`. Empty ids or an empty
  generation list do not mean missing when the corresponding state reports a
  read failure. A missing store root yields an empty list; failure to open or
  completely enumerate an existing root is refused with `PLUGIN_IO`.
- `status NAME` reports the named plugin's `current` and `last_good` ids,
  `generations` count and the same state fields. It refuses an `unreadable` or
  `corrupt` part with `PLUGIN_IO`, while `list` reports those per-plugin states.
  A missing named plugin is `PLUGIN_NOT_INSTALLED`. Status scans the store but
  verifies no signatures, hashes no executables and starts nothing; `work`
  reports `scanned`, `verified` (0) and `hashed` (0). These state reads do not
  establish that a generation's signed files verify.
- `switch` verifies the generation again, sets `last-good` to the previous
  `current`, then points `current` at the generation. Switching to the
  generation that is already current changes nothing.
- `rollback` verifies the `last-good` generation again and points `current` at
  it.

`install`, `switch` and `rollback` are owner commands and are never accepted
from a mesh peer. Their authority is the publisher signature checked against
the owner's publisher key file on every install, switch and rollback; the node daemon
state is untouched.

## Publisher keys and first use

The behavior below was measured on an installed release on 2026-10-18.

- `z23 plugin keygen <path>` writes the key file and prints its public key as
  64 lowercase hex characters.
- Install accepts only plugins signed by the publishers listed in `~/.z23/plugins/publisher_keys`,
  one lowercase hex public key per line. The permission rule for the publisher key file
  and the store directories is in [Permissions](#permissions); a violation is
  refused with `PLUGIN_KEYS_INSECURE`.
- `z23 plugin publisher <64-hex-public-key>` appends the key to `publisher_keys`,
  creating `~/.z23` and `~/.z23/plugins` at mode 0700 and a new file at mode
  0600. A key already listed is reported as `already_listed` and nothing is
  written. Existing directories or a publisher key file that break the rule in
  [Permissions](#permissions) are refused with `PLUGIN_KEYS_INSECURE`; a key
  that is not 64 lowercase hex characters is refused with `PLUGIN_ARGUMENT`.
  The `plugin keygen` reply names this command as its next step.
- `z23 plugin install <manifest>` verifies and stores a generation but does not
  change `current`. Until `z23 plugin switch <name> <generation>` selects one,
  `z23 plugin call` answers `PLUGIN_NO_GENERATION`. `z23 plugin list` shows the
  stored generations and `current_state`.

```sh
z23 plugin keygen ./publisher.key
z23 plugin publisher <64-hex-public-key>      # keygen replies with this as its next step
z23 plugin pack ./up --name=upper --version=1.0.0 --key=./publisher.key --interface=2 --dir=dist
z23 plugin install dist/upper.plugin.json
z23 plugin list
z23 plugin switch upper <128-hex generation>
z23 plugin call upper --stdin=abc          # run.stdout is "ABC"
```

## Running a plugin

`z23 plugin run NAME` verifies the `current` generation again and starts its
executable as a confined child. It runs until interrupted, or for the given
number of seconds (1 to 86400); `SIGHUP` restarts only this plugin on the
current generation (`plugin_run_reload`). The daemon is not contacted. Linux
only: other hosts refuse with `PLUGIN_RUN_PLATFORM`.

**Requirements.** Linux with seccomp and Landlock ABI 3 or newer (kernel 6.2),
because ABI 3 is the first to handle file truncation; below that
`z23 plugin run` refuses with `PLUGIN_RUN_SANDBOX` and starts nothing.

**Image.** The executable must be a static ELF (no `PT_INTERP`). Each start
verifies the generation again and takes the executable's SHA3-512 from the
manifest whose signature was just verified (one read of the manifest and
signature). The executable is then opened once and hashed through that
descriptor; a symbolic link, a non-regular file or bytes that differ from the
signed SHA3-512 are refused. The launcher pins a descriptor to the same inode,
proves its SHA3-256 and file identity against the hashed one, and starts the
plugin with `fexecve` from that pinned descriptor, so the bytes that run are
the bytes that were signed.

**Confinement.** `no_new_privs`; limits of 256 MiB address space, 300 CPU
seconds, 1 MiB per file, 64 descriptors and no core files; Landlock that allows
reading and executing the image and, when the manifest grants `fs.read` or
`fs.write`, access to the data directory only (read-only for `fs.read`; read,
write, create and truncate for `fs.write`); and a seccomp deny-list that kills
the process on the socket family, `ptrace` and `process_vm_*`, the mount and
namespace calls, `bpf`, kernel module and keyring calls, `io_uring`,
`fork`/`vfork`, `setsid`/`setpgid`, `open_by_handle_at`, signalling other
processes (`kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`, `pidfd_open`,
`pidfd_send_signal`, `pidfd_getfd`) and the metadata calls Landlock does not
cover (`chmod`, `fchmod`, `fchmodat`, `fchmodat2`, the `setxattr` and
`removexattr` families, `utimensat`, `utimes`, `futimesat`). Threads are
allowed (`clone` with `CLONE_THREAD`); `clone3` answers `ENOSYS`; mappings that
are both writable and executable are refused. `stdin`, `stdout` and `stderr` are
`/dev/null`. The child starts with an empty signal mask and every signal at its
default action, and is killed if the supervisor exits; the parent-death signal
follows the thread that spawned it, so a supervisor that spawns from a worker
thread must keep that thread alive. `abort()`, `raise()` and `pthread_kill` end
as `SIGSYS` under this profile, because they signal through `tgkill`. The caller
owns process-wide signal state: `SIGCHLD` must be at its default action while a
run is open, otherwise the kernel discards the plugin's exit status and the
supervisor reports it as lost (exit code -1, signal 0). `z23 plugin run` sets
this up.

**Descriptors.** The child holds no descriptor except the ones its manifest
grants, numbered from 3 in this order, and announces them in the environment
variable `Z23_PLUGIN_FDS` (the only variable set), for example
`control=3,data.dir=4,log=5`:

| Name | Granted | Descriptor |
| --- | --- | --- |
| `control` | always | A stream socket to the supervisor. |
| `data.dir` | `fs.read` or `fs.write` | `~/.z23/plugins/NAME/data`, opened as a directory; created with mode 0700 when absent. |
| `log` | always | Write end of a pipe; each line is printed to the supervisor's standard error prefixed with the plugin name, control bytes other than tab replaced by `?`. |

`clock` needs no descriptor. `net.client`, `net.server`, `process.spawn` and
`ui.panel` have no descriptor yet and are refused with
`PLUGIN_RUN_CAPABILITY`, naming the capability. `argv` is
`<image> --resident <launch nonce>`.

**Health ping.** On the control socket the supervisor sends an 81-byte frame:
the 16-byte magic `z23-plg-ping-v1` (NUL padded) and a fresh 64-hex token with
its NUL. The plugin answers with one `z23-res-run-v1` result frame
(`struct resident_result_header` from `platform/resident_launch.h`) that carries
the launch nonce and a 64-byte payload equal to the token. A reply under another
nonce or token does not count. The stop frame `z23-res-stop-v1` has the same
size; the plugin should exit when it reads one. A ping unanswered for 2 s is
missed; 2 consecutive misses kill the child.

**Restart.** An exit or a kill after missed pings restarts the child after 250
ms, doubling per consecutive crash up to 30 s. A child that stays healthy for
10 s clears the crash count and the delay. Three consecutive crashes of one
generation restore the `last-good` generation once, provided `current` still
names that failing generation. The comparison and restoration share the store's
mutation lock, so a newer selection is preserved. Explicit `rollback` remains
unconditional. After automatic restoration, `current` names the restored
generation; if there is no `last-good` generation, or it also
crashes, the supervisor keeps retrying at the capped delay and changes no link.

<!-- claim: symbol-present plugin_store_rollback_if_current contexts/commons/modules/plugin/src/plugin_store.c # automatic fallback compares selection under lock -->

**Result.** The command reports `generation`, `restarts`, `pings_ok`,
`fell_back` and the last `detail`. `PLUGIN_RUN_*` refusals carry a next action;
a store refusal (for example `PLUGIN_EXE_HASH`) is reported under its own code.

## One-shot plugins (interface 2)

A plugin whose manifest has `interface_version` 2 is a plain program, not a
resident daemon: `z23 plugin call NAME` runs its `current` generation once with
`stdin` in, and returns the exit code or signal, `stdout`, `stderr` (bounded
like `lab.run`), `elapsed_ms`, and the plugin's `name`, `version`, `sha3_512` and
`generation`. `pack` takes `--interface=1|2` (default 1); `install` and `switch`
accept both versions and refuse any other.

```sh
cc -std=c23 -O1 -static -o upper upper.c
z23 plugin keygen ./publisher.key          # then: z23 plugin publisher <printed public_key>
z23 plugin pack ./upper --name=upper --version=1.0.0 --key=./publisher.key --interface=2 --dir=./dist
z23 plugin install ./dist/upper.plugin.json
z23 plugin switch upper <128-hex generation>
z23 plugin call upper --stdin=abc          # run.stdout is "ABC"
```

- The signature, publisher key and executable SHA3-512 are verified again immediately
  before each start; a changed executable is refused with `PLUGIN_EXE_HASH` and
  never runs.
- The program runs through the lab's confined runner (see
  [LAB.md](LAB.md#confinement)): Landlock, seccomp, no network, no `fork`, a
  private working directory removed afterwards, resource limits. Declared
  capabilities are recorded and verified but grant nothing beyond that.
- `call` takes `stdin` (at most 65536 bytes), `args` (at most 32 strings) and
  `timeout_ms` (1 to 60000, default 5000).
- `plugin run` refuses an interface 2 plugin and `plugin call` refuses an
  interface 1 plugin, both with `PLUGIN_INTERFACE`.
- Linux only: other hosts refuse with `PLUGIN_RUN_PLATFORM`; a host without
  Landlock and seccomp refuses with `PLUGIN_RUN_SANDBOX`.

## Showing installed plugins in mesh status

Off by default. With `-meshstatusplugins`, the signed capsule that `z23 ops
mesh status` returns carries a `plugins` block: for up to 8 installed plugins,
the name and the first 16 hex characters of the `current` and `last-good`
generation ids, read from `~/.z23/plugins` and refreshed at most once a minute
in the background (before the first read the block says `available=false`,
`reason=not_yet_read`). When on, every paired machine, not only your own, that
sends a status request receives those names and prefixes, and may store them
in its `node.db`. Nothing can be installed, switched or run through it.

## Finding plugins: the signed index

No central registry says which plugins exist. A publisher signs a small index
entry for each plugin generation; anyone can collect entries into a directory
and search it. The index is a claim about where to look, never an install:
`z23 plugin search` fetches, installs and runs nothing, and a `pinned` mark
only says the publisher key is in a key file you chose.

```sh
z23 plugin index_add --root=<64-hex package root> \
    --manifest=./dist/hello.plugin.json --key=./publisher.key --index=./plugin-index
z23 plugin search --name=hello --cap=clock --index=./plugin-index \
    --publishers=$HOME/.z23/plugins/publisher_keys
```

`index_add` first verifies `hello.plugin.json` and `hello.plugin.sig` under the
signing key itself, so an entry never vouches for a plugin its own key did not
sign. `--root` is the package root of the published plugin (a root carrying
`NAME`, `NAME.plugin.json`, `NAME.plugin.sig` and `LICENSE`).

### Entry

One file per entry, named `<SHA3-512 of its bytes>.plugin-index.json`, at most
2048 bytes, canonical and byte-exact (one line, LF-terminated):

```json
{"schema":"z23.plugin.index.v1","name":"hello","version":"1.0.0","interface_version":2,"capabilities":["clock"],"root":"<64 hex>","publisher":"<64 hex>","timestamp":1760000000,"signature":"<128 hex>"}
```

The signature is Ed25519 by the publisher key over the 64-byte SHA3-512 of the
bytes `z23.plugin.index.v1`, one NUL byte, and the entry text up to and
including the timestamp value. The parser accepts an entry only if encoding the
parsed fields reproduces the input bytes, so unknown, repeated or reordered
keys, whitespace, escapes and upper-case hex are all malformed.

### Search rules

- Every entry is verified against its own publisher key; a failure is listed
  under `refused` with `PLUGIN_INDEX_MALFORMED` or `PLUGIN_INDEX_BAD_SIGNATURE`,
  never as a result.
- Byte-identical copies are folded (`duplicates`).
- Per (publisher, plugin name) the highest version wins; versions compare
  numerically per digit run, not as full SemVer. Entries are read in timestamp
  order. A lower version after a higher one is refused as
  `PLUGIN_INDEX_ROLLBACK`; the same version with a different root, interface or
  capabilities is refused as `PLUGIN_INDEX_EQUIVOCATION` and the first one seen
  stays. `index_add` applies the same two refusals against the directory.
- `publisher_status` is `pinned` when the publisher key is listed in the
  `--publishers` file (same format and permissions as `publisher_keys`; an
  empty file pins nothing), otherwise `unpinned`. An unreadable, insecure or
  malformed key file is refused (`PLUGIN_INDEX_PINS`), not read as empty.

### Carrying the index over the fleet

The index directory is a flat set of small, content-named, individually signed
files plus (for a package root) a `LICENSE`, so it needs no new transport: it
is an ordinary package root. A node that wants to share an index builds that
directory into a package with the existing `zcode` flow (see
[C23_COMMONS_QUICKSTART.md](../commons/C23_COMMONS_QUICKSTART.md): `zcode
create`, then `zcode network publish` of a `zclassic23.package` POINTER and a
PROVIDER record), and a peer fetches that root with `zcode package fetch` and
points `--index` at the checkout. Peers can merge several fetched directories
by copying files, because duplicates fold and every entry verifies itself.
Not done here: the POINTER publish gate asks for local reproduction evidence,
so whether a data-only root passes it, and a well-known index name so a node can
find other nodes' indexes, are separate steps. Local `index_add` and `search`
need none of them.
Both leaves are never-remote.

## Refusal codes

Every refusal carries `error.code` and `error.next_action`.

| Code | Meaning |
| --- | --- |
| `PLUGIN_ARGUMENT` | Missing or malformed argument, or `HOME` is not absolute. |
| `PLUGIN_NO_KEYS` | `publisher_keys` is absent or names no key. |
| `PLUGIN_KEYS_MALFORMED` | A `publisher_keys` line is not 64 hex characters. |
| `PLUGIN_MANIFEST_MISSING` | The manifest file does not exist. |
| `PLUGIN_MANIFEST_INVALID` | Not JSON, wrong schema, or a field outside its rules. |
| `PLUGIN_MANIFEST_DUPLICATE_KEY` | A manifest key appears twice. |
| `PLUGIN_MANIFEST_UNKNOWN_KEY` | A manifest key is not in the schema. |
| `PLUGIN_SIG_MISSING` | The signature file does not exist. |
| `PLUGIN_SIG_INVALID` | Signature file is malformed or has unknown or repeated keys. |
| `PLUGIN_SIG_ALG` | `sig_alg` is not `ed25519`. |
| `PLUGIN_KEY_UNKNOWN` | The signing key is not in `publisher_keys`. |
| `PLUGIN_SIG_BAD` | The signature does not verify for the manifest bytes. |
| `PLUGIN_EXE_MISSING` | The executable does not exist. |
| `PLUGIN_EXE_HASH` | The executable's SHA3-512 differs from the manifest. |
| `PLUGIN_NOT_INSTALLED` | No plugin of that name is stored. |
| `PLUGIN_NO_GENERATION` | The named generation is not stored. |
| `PLUGIN_NO_LAST_GOOD` | No `switch` has recorded a last-good generation. |
| `PLUGIN_KEYS_INSECURE` | `publisher_keys` or the store has a wrong owner, is group or world writable, or contains a symbolic link or non-regular file. |
| `PLUGIN_KEY_MISSING` | `pack` was given a key file that does not exist. |
| `PLUGIN_KEY_INSECURE` | The key file is not a regular private file owned by you, is a link/reparse point, or its required Windows parent/ACL is not private. |
| `PLUGIN_KEY_MALFORMED` | The key file is not exactly 32 bytes. |
| `PLUGIN_KEY_EXISTS` | `keygen` never overwrites an existing path. |
| `PLUGIN_IO` | A file operation failed; check permissions and free space. |
| `PLUGIN_INTERFACE` | `plugin run` was given an interface 2 plugin, or `plugin call` an interface 1 plugin. |
| `PLUGIN_RUN_ARGUMENT` | `run` was given no valid plugin name. |
| `PLUGIN_RUN_PLATFORM` | Confined plugin processes are available on Linux only. |
| `PLUGIN_RUN_CAPABILITY` | The manifest grants a capability that has no descriptor yet. |
| `PLUGIN_RUN_SPAWN` | The kernel refused the confined start (Landlock or seccomp unavailable). |
| `PLUGIN_RUN_SANDBOX` | The kernel lacks Landlock ABI 3 or seccomp; plugins are not started unconfined. |
| `PLUGIN_RUN_FAILED` | Supervision ended; the evidence line says why. |


## Builder attestations

A publisher signature proves who published an executable. An attestation
proves an independent builder compiled the same source package root and got
the same bytes. `plugin attest` and `plugin attest_verify` are owner-only,
never remote, read and write files only, and are not wired into `install`,
`switch` or any fetch: they decide nothing until a caller asks.

```sh
z23 plugin attest ./build/hello --name=hello --version=1.0.0 \
    --source-root=<64 hex source package root> --toolchain=gcc-14-linux-x86_64 \
    --key=./builder.key --dir=./attest
z23 plugin attest_verify ./dist/hello.plugin.json --attestations=./attest \
    --builders=./builders.pin --threshold=2
```

`attest` hashes the image you built (SHA3-512) and writes
`NAME-<first 16 hex of the builder key>.attest.json`: one canonical line

```json
{"schema":"z23.plugin.attest.v1","name":"hello","version":"1.0.0","source_root":"<64 hex>","toolchain":"gcc-14-linux-x86_64","image_sha3_512":"<128 hex>","builder_key":"<64 hex>","signature":"<128 hex>"}
```

The builder key file is the same 32-byte Ed25519 seed as a publisher key. The
signature covers SHA3-512 of the domain tag `z23.plugin.attest.v1`, a NUL and
every record byte before `,"signature"`. There is no timestamp, so equal
inputs give byte-identical files. The parser accepts exactly the bytes the
encoder writes and refuses everything else (`PLUGIN_ATTEST_MALFORMED`).
Toolchains are not compared across builders; `toolchains` in the reply counts
the distinct ones, because the same bytes from different toolchains is the
stronger claim. The record is Ed25519 only: the ZRS1 hybrid container signs a
release document, not an arbitrary prefix, and does not compose here.

`builders.pin` is a trust root, read like `publisher_keys`: owner-only, one
64-character lowercase hex public key per line, `#` comments, a repeated key
counts once. `attest_verify` accepts only when at least `threshold` distinct
pinned builder keys attest the manifest's `sha3_512` for one source root
(`--source-root` names it; otherwise the first record does). Use one
attestation directory per plugin version. It checks attestations, not the
publisher signature; `install` still does that. Every record is checked in
sorted file order; the first bad one refuses the whole directory:

| Code | Meaning |
| --- | --- |
| `PLUGIN_ATTEST_THRESHOLD_INVALID` | The threshold is below 1. |
| `PLUGIN_ATTEST_THRESHOLD_EXCEEDS_PINS` | The threshold is above the distinct pinned builders. |
| `PLUGIN_ATTEST_MALFORMED` | A record is not the canonical encoding, or a `*.attest.json` file name is 256 bytes or more (refused, never skipped). |
| `PLUGIN_ATTEST_IO` | The attestation directory could not be read completely; a read error partway never counts as a shorter directory. |
| `PLUGIN_ATTEST_SIG_BAD` | A record's signature does not verify under its builder key. |
| `PLUGIN_ATTEST_SUBJECT_MISMATCH` | A record names another plugin name or version. |
| `PLUGIN_ATTEST_BUILDER_UNPINNED` | A record's builder key is not in the pin file. |
| `PLUGIN_ATTEST_DUPLICATE_BUILDER` | Two records carry the same builder key. |
| `PLUGIN_ATTEST_HASH_MISMATCH` | A record's image hash is not the manifest's `sha3_512`. |
| `PLUGIN_ATTEST_SOURCE_ROOT_MISMATCH` | Records, or `--source-root`, name different source roots. |
| `PLUGIN_ATTEST_BELOW_THRESHOLD` | Fewer distinct pinned builders attest than the threshold. |
| `PLUGIN_ATTEST_PINS_MALFORMED` | The pin file has a line that is not a 64 hex key, or over 256 keys. |

A missing or group-writable pin file, an unreadable manifest or key and the
like keep the store's own `PLUGIN_*` code. The library entry is
`plugin_attest_verify_dir` in `plugin/plugin_attest.h`.

## Tests

```sh
make CC=gcc-14 t-fast-exact ONLY=plugin_store
make CC=gcc-14 t-fast-exact ONLY=plugin_run
make CC=gcc-14 t-fast-exact ONLY=plugin_call
make CC=gcc-14 t-fast-exact ONLY=plugin_attest
```
