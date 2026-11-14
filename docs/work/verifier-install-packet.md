<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0. -->

# Fixed-result verifier: root install and qualification packet

This packet installs and qualifies the separate-account verifier for one
compile: the test-fast, non-LTO `platform/modules/base/src/result.c`. It has
five binaries:

| Binary | Runs as | Job |
| --- | --- | --- |
| `z23-fixed-result-launcher` | root | preflight, `pins-encode`; writes launch receipts |
| `z23-fixed-result-worker` | `z23vcc` (60093) in the jail | the compile |
| `z23-tree-closure` | root | image tree roots |
| `z23-fixed-result-signer` | `z23verify` (60092) | seals a launch into signer-private staging |
| `z23-fixed-result-publisher` | root | adds a staged record to the store, no-clobber |

The byte contract is in [`verifier-contract-v2.md`](./verifier-contract-v2.md).
The launcher's own staging notes are in
[`tools/verify/README.fixed-result-launcher.md`](../../tools/verify/README.fixed-result-launcher.md).
The design and threat model are in [`separate-verifier.md`](./separate-verifier.md).

Nothing here starts a service or grants reuse. Every unit is installed
disabled. Installation and activation each need their own operator grant.

## 0. What is ready and what is blocked

Ready:

- building all five binaries from a signed commit;
- accounts, directories and trust files;
- the signer key and its pinned public key;
- the signer and publisher units;
- preflight up to its fixed `isolation_unqualified` refusal;
- every identity and custody refusal in section 9.

Blocked. These steps stay cold until the slices land:

- **B1. No launch request mode.** The launcher has no request/receipt mode;
  it only runs `preflight` and `pins-encode`. The live request (Q4) and every
  RED fixture that needs a compile wait for that slice.
- **B2. No seccomp filter generator.** No generator is in the tree for
  `/etc/z23verify/fixed_result.seccomp.bpf`. A reviewed filter must be
  supplied and pinned.
- **B3. No image builders.** Section 5 gives manual recipes for the
  source, tool and check images.
- **B4. Receiver HIT command.** The developer-UID receiver HIT (Q6) uses the
  receiver slice's `zcc` lookup. Its exact command belongs to that slice.

The no-root dress rehearsal (section 1) runs the same chain today. It runs
under one UID, and only with the `ZCL_TESTING` fixture flag.

## Root vs non-root

Root is required for:

- sections 3–8;
- Q1–Q5, except the lines marked "developer";
- teardown.

Root is not required for:

- section 1 (the dress rehearsal);
- section 2 (build and hash);
- `pins-encode`;
- the developer-UID checks in Q2 and Q6.

Run every root command in a root shell with `umask 022` and `set -euo pipefail`.

## 1. Dress rehearsal (developer, no root)

```sh
cd /path/to/zclassic23          # the signed commit under review
devbuild --wait make -j8 t-fast-exact ONLY=verify_signer
```

Expected: every `verify signer:` line prints `OK`, plus one evidence line:

```text
verify signer evidence: object_bytes=10128 object_sha3=268e7e07f6accd32...
  receipt_sha3=a0efdf8e... store_key=a0315801... record_sha3=5190cdaa...
  verdict=hit cold_equal=1
```

What the rehearsal does:

1. The real worker runs `qualify` and compiles `result.c` with the real
   `tools/verify/fixed_result_fast.args`.
2. A fixture launcher writes launch receipt v2 and failure receipt v2.
3. The signer seals.
4. The publisher publishes.
5. The receiver runs its own cold `-E` and `-c` through `/proc/self/fd/N`
   paths.
6. The receiver rebuilds key v2 and looks it up with
   `zcl_verify_store_lookup_site_fixture`: production's own policy, pins and
   store walk, under a test-owned anchor holding `etc/z23verify` and
   `var/lib/z23verify`. It gets a HIT whose object is byte-equal to its cold
   object. Without the fixture flag the same lookup refuses
   `store_owner_same_uid`.

The object hash holds only for the pinned `result.c` and headers. The worker
hardcodes their SHA3s, so editing them fails the group until they are
re-pinned. The failure prints the worker's refusal and the exact re-pin steps.

## 2. Build from a signed commit and record hashes (no root)

```sh
C=<reviewed commit sha>
R=/path/to/zclassic23
git -C "$R" verify-commit "$C"                  # must print a good signature
B=$HOME/z23verify-build/$C; mkdir -p "$B/a" "$B/b"
for side in a b; do
  mkdir "$B/$side/src"
  git -C "$R" archive "$C" | tar -x -C "$B/$side/src"
  ( cd "$B/$side/src"
    INC="-Itools $(for d in platform/modules/*/include \
          core/modules/*/include core/math/include; do printf -- '-I%s ' "$d"; done)"
    CF="-std=c23 -O2 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror \
        -ffile-prefix-map=$PWD=/zclassic23"
    FR="tools/verify/fixed_result_contract.c tools/verify/fixed_result_key_v2.c \
        platform/modules/sha3/src/sha3.c platform/modules/codec/src/cursor.c"
    K="tools/verify/fixed_result_trust.c tools/dev/verify_store.c \
       tools/dev/verify_attest.c $FR core/modules/crypto/src/ed25519.c \
       core/modules/crypto/src/sha512.c core/modules/crypto/src/random_secret.c \
       core/modules/core/src/random.c platform/modules/platform/src/rng.c \
       platform/modules/base/src/cleanse.c platform/modules/base/src/log_level.c \
       platform/modules/base/src/safe_alloc.c"
    cc $CF $INC -o ../z23-fixed-result-launcher tools/verify/fixed_result_launcher.c \
       $FR platform/modules/platform/src/os_proc.c
    cc $CF $INC -o ../z23-fixed-result-worker tools/verify/fixed_result_worker.c \
       $FR platform/modules/platform/src/os_proc.c
    cc $CF $INC -o ../z23-tree-closure tools/verify/tree_closure.c $FR \
       platform/modules/base/src/safe_alloc.c platform/modules/base/src/log_level.c
    cc $CF $INC -o ../z23-fixed-result-signer tools/verify/fixed_result_signer_main.c \
       tools/verify/fixed_result_signer.c $K
    cc $CF $INC -o ../z23-fixed-result-publisher \
       tools/verify/fixed_result_publisher_main.c tools/verify/fixed_result_publisher.c \
       tools/verify/fixed_result_signer.c $K )
done
( cd "$B/a" && openssl dgst -sha3-256 -r z23-* ) > "$B/hashes.a"
( cd "$B/b" && openssl dgst -sha3-256 -r z23-* ) > "$B/hashes.b"
cmp "$B/hashes.a" "$B/hashes.b" && cat "$B/hashes.a"   # identical, or stop
```

Record `hashes.a` in the review. Every later install step compares against it.

## 3. Accounts (root)

```sh
getent passwd 60092 60093 && exit 1     # both UIDs must be free
groupadd --system --gid 60092 z23verify
useradd  --system --uid 60092 --gid 60092 --no-create-home \
         --home-dir /nonexistent --shell /usr/sbin/nologin z23verify
groupadd --system --gid 60093 z23vcc
useradd  --system --uid 60093 --gid 60093 --no-create-home \
         --home-dir /nonexistent --shell /usr/sbin/nologin z23vcc
id z23verify; id z23vcc      # uid=gid=60092 / 60093, no supplementary groups
```

## 4. Directories and binaries (root)

Stage the reviewed files in `/root/z23verify-staging`: root-owned, mode 0700,
each file root-owned, nlink 1, mode 0444 or 0555.

```sh
S=/root/z23verify-staging; B=<the build dir from section 2>/a
install -d -o root -g root -m 0700 "$S"
install -o root -g root -m 0555 "$B/z23-fixed-result-launcher" "$S/fixed_result_launcher"
install -o root -g root -m 0555 "$B/z23-fixed-result-worker"   "$S/fixed_result_worker"
install -o root -g root -m 0555 "$B/z23-tree-closure"          "$S/z23-tree-closure"
install -o root -g root -m 0444 <src>/tools/verify/fixed_result_fast.args "$S/"
install -o root -g root -m 0444 <src>/tools/verify/fixed_result_launch_policy.v1 "$S/"
install -o root -g root -m 0444 <reviewed filter> "$S/fixed_result.seccomp.bpf"   # B2
openssl dgst -sha3-256 "$S"/fixed_result_* "$S"/z23-tree-closure   # == hashes.a
```

The profile must hash to `41d985cfdd672074e903b3ff05efec58f4cb4c8d0057a685207d69f007bac082`.
The launch policy must hash to `1315fa7fb2a718829a881955bf7415c3b4bdabc30d89ddeda0e0781983cc4abe`.

The signer and publisher are installed directly:

```sh
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0555 "$B/z23-fixed-result-signer"    /usr/local/libexec/
install -o root -g root -m 0555 "$B/z23-fixed-result-publisher" /usr/local/libexec/
V=/var/lib/z23verify
install -d -o root      -g root      -m 0755 /etc/z23verify $V $V/store $V/locks $V/images
install -d -o root      -g root      -m 0700 $V/launches $V/publish-tmp $V/conflicts
install -d -o z23verify -g z23verify -m 0700 $V/key $V/staging
install -o root -g root -m 0644 /dev/null $V/locks/fixed_result.lock
```

## 5. Images (root; B3)

The images are root-owned, not group- or world-writable, and contain no
symlink that escapes the tree.

- **Source image.** `$V/images/fixed_result/source` is the signed commit's
  tree:

  ```sh
  git -C "$R" archive "$C" | tar -x -C …/source
  chown -R root:root …/source
  chmod -R go-w …/source
  ```

  The jail mounts it read-only at `/zclassic23`.
- **Tool image.** `$V/images/fixed_result/tool` holds the GCC 14 closure the
  compile reaches:
  - the driver `/usr/bin/cc`, and `$(cc -print-prog-name=cc1)`, `as` and
    `ld.so`;
  - every DSO that `ldd` lists for each of those;
  - the specs and start files;
  - the system include trees.
- **Check image.** `$V/images/fixed_result/check` holds:
  - the reviewed signer and publisher;
  - the receiver's `zcc` and key constructor;
  - the pinned current-main proof executor.

Record each tree's roots:

```sh
for i in source tool check; do
  /usr/local/libexec/z23-tree-closure hash $V/images/fixed_result/$i 0
done    # prints tree_sha3=… content_sha3=… per image
```

## 6. bwrap or a root mount namespace (root)

On this host `bwrap` is absent and `kernel.apparmor_restrict_unprivileged_userns=1`.
The launcher runs as root, so its namespaces are privileged; the userns
restriction does not apply to it. Install the distribution package and pin
its bytes:

```sh
apt-get install --no-install-recommends bubblewrap
stat -c '%U:%G %a %h' /usr/bin/bwrap              # root:root 755 1, not setuid
openssl dgst -sha3-256 /usr/bin/bwrap              # becomes bwrap_sha3
```

The alternative is a root-created mount namespace built by the launcher
itself (`unshare(CLONE_NEWNS|…)` before dropping to 60093). That needs a
reviewed launcher change and a new `bwrap` pin semantics. Do not loosen the
AppArmor sysctl for this.

## 7. Signer key and trust files (root, key generated as z23verify)

The seed is created by `z23verify` and never leaves that account:

```sh
runuser -u z23verify -- sh -c 'umask 077 &&
  head -c 32 /dev/urandom > /var/lib/z23verify/key/signer.seed &&
  chmod 0400 /var/lib/z23verify/key/signer.seed'
stat -c '%U %a %h %s' /var/lib/z23verify/key/signer.seed   # z23verify 400 1 32
runuser -u z23verify -- /usr/local/libexec/z23-fixed-result-signer pubkey \
  > /etc/z23verify/verifier.pub.new                         # 64 hex + LF
```

The box signer key is the developer's per-box proof key, which candidate code
can read. The developer runs `z23-dev dev proof signer`:

- if `key_present` is true, write its `pubkey` value followed by a line feed;
- otherwise write `none` followed by a line feed.

```sh
printf '%s\n' <box pubkey hex or none> > /etc/z23verify/box_signer.pub.new
cmp -s /etc/z23verify/verifier.pub.new /etc/z23verify/box_signer.pub.new && exit 1
printf 'z23verify.store.v1\nsigner_uid=60092\npublisher_uid=0\n' \
  > /etc/z23verify/store.policy.new
```

The pins take the twelve roots in pins v2 order. `pins-encode` needs no root.
It refuses a zero root, the strict profile or another environment by its
contract token.

| Root | Source |
| --- | --- |
| `source_content` | the source `content_sha3` from section 5 |
| `profile_args` | `41d985cfdd672074e903b3ff05efec58f4cb4c8d0057a685207d69f007bac082` |
| `source_image` | the source `tree_sha3` |
| `tool_image` | the tool `tree_sha3` |
| `worker` | the worker's hash in `hashes.a` |
| `launcher` | the launcher's hash in `hashes.a` |
| `check_image` | the check `tree_sha3` |
| `environment` | `ed1c9f968470f56dba60178ad62efc24ea1440b0cf2409c51f6d7f79e09bc507` (fixed; any other refuses `contract_env_mismatch`) |
| `policy` | `1315fa7fb2a718829a881955bf7415c3b4bdabc30d89ddeda0e0781983cc4abe` |
| `seccomp_filter` | the reviewed filter's SHA3 |
| `bwrap` | `/usr/bin/bwrap`'s SHA3 |
| `tree_checker` | the tree-closure hash in `hashes.a` |

```sh
"$B/z23-fixed-result-launcher" pins-encode <12 hex in the order above> \
  > "$S/fixed_result.pins"
chown root:root "$S/fixed_result.pins"; chmod 0444 "$S/fixed_result.pins"
platform/deploy/fixed-result-launcher-install.sh install   # from the reviewed tree
# expected: fixed_result_installed_material=1 service_started=0 signed_observation=0 attest_eligible=0
for f in verifier.pub box_signer.pub store.policy; do
  mv /etc/z23verify/$f.new /etc/z23verify/$f
done
chown root:root /etc/z23verify/*; chmod 0444 /etc/z23verify/store.policy
chmod 0644 /etc/z23verify/verifier.pub /etc/z23verify/box_signer.pub
```

Custody check. Every line must match:

```sh
for p in / /etc /etc/z23verify /var /var/lib /var/lib/z23verify; do
  stat -c '%n %U %a' "$p"; done          # root, no group/world write
stat -c '%n %U:%G %a %h' /etc/z23verify/*
# fixed_result.pins, store.policy, fixed_result_fast.args,
# fixed_result.policy, fixed_result.seccomp.bpf: root:root 444 1
# verifier.pub, box_signer.pub: root:root 644 1
```

## 8. Units, installed disabled (root)

The signer gets an empty capability set. The publisher's only capability is
`CAP_DAC_READ_SEARCH`: read and search permission override, nothing else. It
needs that to read the signer's mode-0700 staging, and it writes only
root-owned directories.

The alternative was group-readable staging (mode 0750/0440 with group root).
That was rejected because it widens exposure:

- every process in the staging group could read unpublished signed records;
- the staging directory could no longer be signer-private (mode `& 0077 == 0`),
  which is the check both the signer and the publisher make;
- the signer's `umask 077` and its signer-private check on `key/` and
  `staging/` would have to diverge.

The publisher unit also sets `InaccessiblePaths=/var/lib/z23verify/key`,
because the read override would otherwise reach `signer.seed`.

With the capability, the widening is confined to one short-lived root
process that verifies every byte it reads.

`ReadWritePaths=` covers all of `/var/lib/z23verify`. The publisher's
`RENAME_NOREPLACE` from `publish-tmp/` to `store/` would cross bind mounts and
refuse `publisher_cross_device` if the paths were split.

```ini
# /etc/systemd/system/z23-fixed-result-sign@.service   (PASS launch)
[Unit]
Description=z23 fixed-result signer for launch %i
[Service]
Type=oneshot
User=z23verify
Group=z23verify
OpenFile=/var/lib/z23verify/launches/%i/launch.bin:launch:read-only
OpenFile=/var/lib/z23verify/launches/%i/object.o:object:read-only
OpenFile=/var/lib/z23verify/launches/%i/deps.d:deps:read-only
OpenFile=/var/lib/z23verify/launches/%i/stderr.bin:stderr:read-only
OpenFile=/var/lib/z23verify/launches/%i/preprocessed.i:pp:read-only
ExecStart=/usr/local/libexec/z23-fixed-result-signer seal-fds
UMask=0077
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/z23verify/staging
PrivateNetwork=yes
PrivateTmp=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX
SystemCallFilter=@system-service
```

```ini
# /etc/systemd/system/z23-fixed-result-sign-fail@.service   (FAIL launch)
# Same as above, with only three OpenFile= lines, in this order:
#   launch.bin, stderr.bin, preprocessed.i
# and: ExecStart=/usr/local/libexec/z23-fixed-result-signer seal-fail-fds
```

```ini
# /etc/systemd/system/z23-fixed-result-publish@.service   (%i = record sha3)
[Unit]
Description=z23 fixed-result publisher for record %i
[Service]
Type=oneshot
User=root
ExecStart=/usr/local/libexec/z23-fixed-result-publisher publish %i
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/z23verify
PrivateNetwork=yes
PrivateTmp=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
AmbientCapabilities=
# The capability could read key/signer.seed; hide that directory outright.
InaccessiblePaths=/var/lib/z23verify/key
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX
SystemCallFilter=@system-service
```

```sh
systemctl daemon-reload     # do not enable; each start below is explicit
```

## 9. Qualification

- **Q1. Preflight (root).**

  ```sh
  /usr/local/libexec/z23-fixed-result-launcher preflight
  ```

  Expected stdout: `pinned_material_ok=1 attest_eligible=0`.
  Expected stderr: `fixed_result_launcher_refuse=isolation_unqualified`.
  Exit code: 2.
- **Q2. Identities.**

  ```sh
  runuser -u nobody -- /usr/local/libexec/z23-fixed-result-signer pubkey
  #   -> fixed_result_signer_refuse=signer_uid_not_verifier
  /usr/local/libexec/z23-fixed-result-publisher publish $(printf '0%.0s' {1..64})
  #   (developer) -> fixed_result_publisher_refuse=publisher_root_required conflict_recorded=0
  runuser -u z23verify -- /usr/local/libexec/z23-fixed-result-publisher publish …
  #   -> publisher_root_required
  ```
- **Q3. Key pin (root).**

  ```sh
  runuser -u z23verify -- /usr/local/libexec/z23-fixed-result-signer pubkey \
    | cmp - /etc/z23verify/verifier.pub
  ```

  Expected: identical.
- **Q4. One live request (root; blocked on B1).** The launcher writes
  `launches/<id>/` and prints the launch ID.
- **Q5. Seal and publish (root).**

  ```sh
  systemctl start z23-fixed-result-sign@<id>.service
  journalctl -u z23-fixed-result-sign@<id> -o cat
  #   -> fixed_result_signer_sealed=1 verdict=pass exit_code=0 store_key=K record_sha3=R
  systemctl start z23-fixed-result-publish@R.service
  #   -> fixed_result_publisher_published=1 verdict=pass conflict=none
  #      conflict_recorded=0 store_key=K record_sha3=R
  ls -l /var/lib/z23verify/store/K/R    # root 0644 files, root 0755 dir
  ```
- **Q6. Receiver HIT (developer; blocked on B4).** The receiver's own cold
  `-E` gives a HIT on K. The object is byte-equal to its cold `-c`. Run it a
  second time as `z23verify`; it must refuse `store_owner_same_uid`.

RED fixtures. Each must refuse by name before any HIT. The status column
says whether a fixture runs today (**now**) or needs the live request
(**B1**). The `verify_signer` column names the rehearsal case that already
covers it under `ZCL_TESTING`.

| RED | Action | Expected refusal | Status | `verify_signer` case |
| --- | --- | --- | --- | --- |
| cc1 replaced, driver unchanged | swap `cc1` in the tool image | preflight `tool_image_mismatch` | now | — |
| `COMPILER_PATH` or `GCC_EXEC_PREFIX` set | add it to the worker env | none reaches GCC: the worker execs it with its fixed four-entry environment, and a changed compiled-in environment fails `contract_env_mismatch` at startup | B1 | — |
| optional header added | add an absent header to the source image | preflight `source_image_mismatch` | now | — |
| DSO or spec file changed | modify one in the tool image | preflight `tool_image_mismatch` | now | — |
| escaping symlink | link out of any image | tree-closure `symlink_escapes_root` | now | — |
| input changed mid-compile | rewrite a pinned header during compile | worker `pinned_input_changed` | B1 | — |
| wrong verifier key | replace `verifier.pub` | signer `signer_key_not_pinned`; receiver `attest_signer_not_verifier` | now (signer) | key custody |
| verifier key equals box key | set `box_signer.pub` to the verifier key | `trust_verifier_is_box_signer` | now | box pin |
| seed readable by group or world | `chmod 0440` the seed | `signer_key_group_or_world_accessible` | now | key custody |
| receipt not root-owned | `chown` `launch.bin` | `signer_receipt_not_root_owned` | B1 | receipt custody |
| pins drift | re-pin one root | `contract_pin_mismatch` | B1 | trust drift |
| artifact swapped after receipt | replace `object.o` | `contract_receipt_artifact_mismatch` | B1 | artifact swap |
| receipt hash altered | change root `launch.bin` after sealing | `publisher_receipt_not_root_launch` or `attest_receipt_mismatch` | B1 | receipt binding |
| staging owner not signer | `chown` staging to another UID | `publisher_staging_owner_mismatch` | B1 | staging owner |
| symlinked staging entry | replace `object.o` with a symlink | `publisher_staging_entry_unsafe` | B1 | staging links |
| record directory exists | publish R twice | `publisher_record_exists`; history kept | B1 | no-clobber |
| FAIL then PASS | publish a signed FAIL, then the PASS | both published in `store/K/`; publisher reports `conflict=publisher_conflict_fail_exists` and writes an audit note; receiver BLOCK `attest_eligible_conflict` | B1 | FAIL then PASS |
| PASS then FAIL | the reverse | both published; `conflict=publisher_conflict_pass_exists`; the earlier HIT becomes BLOCK `attest_eligible_conflict`, never HIT | B1 | PASS then FAIL |
| key full | more than 96 records under one key | `publisher_store_unsafe` for every further publish; receivers already BLOCK `store_scan_incomplete` past 64 | B1 | — |
| lock held past deadline | `flock -x …/fixed_result.lock sleep 10` | `publisher_lock_deadline` (5 s) | B1 | lock |
| tampered object, dep or stderr in store | edit a stored file | receiver `attest_*_mismatch` | B1 | — |
| wrong argv or cwd | receiver key from another cwd or profile | receiver COLD, `attest_no_observation` | B1 | — |
| record from the developer UID | fixture store owned by the caller | `store_owner_same_uid` | now | developer UID |

## 10. Teardown (root)

```sh
systemctl stop 'z23-fixed-result-sign@*' 'z23-fixed-result-sign-fail@*' \
               'z23-fixed-result-publish@*' 2>/dev/null || true
rm -f /etc/systemd/system/z23-fixed-result-sign@.service \
      /etc/systemd/system/z23-fixed-result-sign-fail@.service \
      /etc/systemd/system/z23-fixed-result-publish@.service
systemctl daemon-reload
rm -f /var/lib/z23verify/key/signer.seed     # proofs go cold: no key admits
rm -rf /var/lib/z23verify /etc/z23verify /root/z23verify-staging
rm -f /usr/local/libexec/z23-fixed-result-{launcher,worker,signer,publisher} \
      /usr/local/libexec/z23-tree-closure
userdel z23verify; userdel z23vcc
```

Receivers read `/etc/z23verify/verifier.pub` and the store on every lookup.
Once both are gone, every lookup is COLD.
