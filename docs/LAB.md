# The one-file lab

`z23 lab` compiles one C23 file, runs it confined, and returns what happened as
one JSON receipt: compiler diagnostics parsed to line and column, exit code or
signal, stdout, stderr, sanitizer findings, and the confinement that was
applied. An agent writes a single `.c` file and gets ground truth in tens of
milliseconds, with no repository, test group or build tree.

Why: [`agent/FLASH_UNIT.md`](agent/FLASH_UNIT.md) records agents finishing 0 of
10 multi-file tasks and 2 of 2 single-file tasks with a pinned test. The lab
makes the second shape available without a pinned test: the program is its own
test, and `lab test` adds expected output.

Linux only. Where Landlock or seccomp cannot be applied, `lab run` and
`lab test` refuse with `LAB_UNCONFINED` and never run the program;
`--compile_only=true` still compiles. Other platforms refuse with
`LAB_UNSUPPORTED`.

## Commands

| Command | Purpose |
|---|---|
| `z23 lab run <file.c>` | compile and run once; receipt `zcl.lab_run.v1` |
| `z23 lab test <file.c> --cases=<json>` | compile once, run each case; receipt `zcl.lab_test.v1` |
| `z23 lab show <root>` | print the stored receipt for a root |
| `z23 lab promote <file.c> --cases=<json> --name=<n> --version=<v> --key=<file>` | sign a file that passes its cases as a one-shot plugin; receipt `zcl.lab_promote.v1` |

`lab run` inputs: `stdin` (string, at most 64 KiB), `args` (at most 32
strings), `sanitize` (default true), `timeout_ms` (default 5000, at most
60000), `mem_mb` (default 256, at most 2048), `fresh`, `compile_only`.
`lab test` takes `cases` (a JSON file path or an inline array of at most 256
objects with `name` and optional `stdin`, `args`, `expect_stdout`,
`expect_exit`) and the same `sanitize`, `timeout_ms`, `mem_mb`, `fresh`.

```
$ z23 lab run tests/fixtures/lab/hello.c        # data member, trimmed of compiler_id
{"root":"59a65c99...eb7f185e","kind":"run","file":"tests/fixtures/lab/hello.c",
 "compile":{"ok":true,"wall_us":349160,"diagnostics":[],"raw_tail":"","detail":""},
 "run":{"ran":true,"exit_code":0,"signal":0,"signal_name":"","timed_out":false,
        "wall_us":3899,"max_rss_kb":6400,"stdout":"hello, lab\n",
        "stdout_truncated":false,"stderr":"","stderr_truncated":false},
 "sanitizer":{"enabled":true,"status":"enabled","findings":0,"first":""},
 "confinement":{"landlock":true,"pidns":true,"landlock_abi":4,"seccomp":true,"no_new_privs":true,
                "network":"denied","filesystem":"private workdir",
                "processes":"no fork; threads only","signals":"own PID namespace"},
 "cache":{"hit":false}}
```

A compile error (`tests/fixtures/lab/compile_error.c`) returns
`compile.ok:false` and one row per diagnostic, and `run.ran:false`:

```
"diagnostics":[{"line":4,"col":12,"severity":"error",
  "message":"'undefined_symbol' undeclared (first use in this function)"},
 {"line":4,"col":12,"severity":"note","message":"each undeclared identifier is
  reported only once for each function it appears in"}]
```

An undefined-behavior finding (`ub.c`) is counted and quoted:

```
"sanitizer":{"enabled":true,"status":"enabled","findings":1,
 "first":"ub.c:9:7: runtime error: signed integer overflow: 1 + 2147483647 cannot be represented in type 'int'\n"}
```

`lab test` on `adder.c` with `adder_cases.json` (three pass, one expectation is
wrong):

```
"passed":3,"failed":1,"cases":[
 {"name":"adds","pass":true,"exit_code":0,"signal":0,"wall_us":4014,"diff":""},
 {"name":"adds negative","pass":true,...},
 {"name":"wrong expectation","pass":false,"exit_code":0,"signal":0,"wall_us":3165,
  "diff":"line 1: expected \"6\\n\" got \"5\\n\""},
 {"name":"no input fails","pass":true,"exit_code":1,...}]
```

A case passes when the program exits with `expect_exit` (default 0), is not
signalled or timed out, and, if `expect_stdout` is given, stdout equals it
exactly. `diff` is the first differing line, at most 512 bytes; all diffs of one
receipt share 16 KiB, and `diffs_omitted` counts those cut.

## Limits

| Limit | Value |
|---|---|
| Source | one regular `.c` file you own, no symlink, at most 256 KiB |
| Compile | `-std=c23 -O1 -g -Wall -Wextra -Werror -pedantic`, libc and libm only, 30 s wall |
| Sanitizers | `-fsanitize=address,undefined`; if the toolchain lacks them the receipt says `sanitizer.status:"unavailable"` and the program is built without |
| Captured output | 64 KiB each for stdout and stderr; `*_truncated` is set when more was written |
| Reply output | the registry caps a reply at 64 KiB, so a receipt carries at most 20000 serialized bytes of stdout, 12000 of stderr and 6144 of compiler output (invalid UTF-8 and control bytes other than newline, tab and carriage return become U+FFFD) |
| Run | `timeout_ms` wall (the process group is killed), CPU seconds `timeout_ms/1000 + 2`, 8 MiB stack, 16 MiB files, 64 descriptors, no core files |
| Memory | `mem_mb` as `RLIMIT_AS` for a plain build; for a sanitized build `ASAN_OPTIONS=hard_rss_limit_mb` (ASan reserves terabytes of address space, so `RLIMIT_AS` cannot apply) |
| Scratch disk | the run's working directory is capped at 64 MiB, checked every 20 ms; exceeding it kills the process group and sets `run.disk_exceeded` |
| `max_rss_kb` | peak resident set of the run, floored at the supervisor's resident size at fork (Linux keeps the larger across exec) |

LeakSanitizer is off (it needs ptrace) and sanitizer reports are not
symbolized (the symbolizer needs fork and exec); stack frames print as module
offsets. UBSan reports carry file, line and column without symbolization.

## Confinement

Compile and run children are forked from the node, then apply in order:
own process group, descriptor scrub, scrubbed environment, rlimits,
`no_new_privs`, PID namespace (run child, when permitted), Landlock, seccomp, `execv`. A setup failure travels over a
close-on-exec pipe, so "could not confine" is never confused with "the program
failed".

- Filesystem (Landlock): the program may read and write inside a fresh private
  workdir under `<state>/run/` and nothing else it can write; it may read and
  execute its own binary and `/lib`, `/lib64`, `/usr/lib`, read
  `/etc/ld.so.cache`, `/proc/self`, `/dev/null`, `/dev/urandom`, `/dev/zero`.
  The workdir is not executable. Reading `/etc/passwd` or the home directory is
  denied.
- Syscalls (seccomp): the session deny-set from `platform/os_sandbox.h` (socket
  family, ptrace, mount and namespace calls, bpf, modules, keyrings,
  `open_by_handle_at`) kills the process with `SIGSYS`; `fork` and `vfork` are
  denied, `clone` only with `CLONE_THREAD`, so threads work and child
  processes do not; `kill` of pid 0, pid -1 and the supervisor returns `EPERM`.
- Network: none (no socket can be created).
- Signals: where unprivileged user namespaces are allowed, the run child enters
  a fresh PID and user namespace (`os_sandbox_pidns_enter`, identity uid map)
  and no process outside the lab is addressable. Where the host refuses them
  (r1 under AppArmor), a seccomp filter
  (`os_sandbox_seccomp_self_signals_only`) allows `kill` and `tgkill` only at
  the program's own pid, so `raise` and `abort` still work, and answers
  `EPERM` to `tkill`, queued signals, `pidfd_open`, `pidfd_send_signal`,
  `ptrace` and `process_vm_readv/writev`. It also refuses the commands that give a
  descriptor an owner or a signal number (`fcntl` `F_SETOWN`, `F_SETOWN_EX`,
  `F_SETSIG`; `ioctl` `FIOSETOWN`, `SIOCSPGRP`, `TIOCSPGRP`), because a ready
  descriptor otherwise signals its owner. The filter is installed in both
  cases. `/proc` outside the workdir is denied by Landlock.
  `confinement.pidns` and `confinement.signals` report which applied.

The compile child is confined the same way (no network, writable only in its
compile directory and the lab compile cache) and keeps `fork` and `exec` for
the compiler driver.

## State and cache

State lives in `$Z23_LAB_DIR`, else `~/.z23/lab`: `receipts/<root>.json`,
`zcc/` (the in-tree compile cache, `tools/zcc.c`, capped at 64 MB) and
transient `cc/` and `run/` directories removed after each call. The compiler
is `build/bin/zcc cc`; without `zcc` beside the node binary the lab calls `cc`
directly.

The root is the SHA3-512 of length-prefixed fields: the source bytes, `sanitize`,
`timeout_ms`, `mem_mb`, and for `run` also `compile_only`, `stdin` and `args`,
for `test` the canonical cases. The same root with the same compiler identity
(path, size and mtime of `cc` and `zcc`) is answered from the stored receipt
with `cache.hit:true`, without compiling or running. The cache keys the inputs,
not the program's behavior: a program that reads the clock or a random source is
replayed, not re-run. Pass `fresh:true` to compile and run again.

## The one-file agent loop

1. Write `solve.c`.
2. `z23 lab run solve.c` and read `compile.diagnostics`; fix by line and column.
3. Add `lab test solve.c --cases=cases.json` until `failed` is 0.
4. Treat `sanitizer.findings > 0` as a bug even when the exit code is 0.
5. `z23 lab show <root>` re-reads any receipt without re-running.

Through MCP (`z23 mcp serve`, no `--checkout` needed) `lab.run` and `lab.test`
run with `z23_run` and an `idempotency_key` in `input`, for example
`{"path":"lab.run","input":{"file":"/abs/solve.c","idempotency_key":"try-1"}}`;
without the key the call is refused with `IDEMPOTENCY_KEY_REQUIRED`. The key
is not part of the root, so a repeat with a new key still answers from the
stored receipt. `lab.show` is a read. `plugin.call` stays CLI-only: it needs
owner authority, which the adapter refuses.

A lab file that reads stdin and writes stdout can be packed unchanged as a
one-shot plugin (`z23 plugin pack --interface=2`) and run with `z23 plugin call`;
see [PLUGINS.md](PLUGINS.md#one-shot-plugins-interface-2). `lab promote` does
the whole path from a tested file.

## Promote a lab file to a plugin

`lab promote` turns one C23 file that passes its cases into a signed one-shot
plugin, in this order, and writes nothing to `dir` unless every gate passes:

1. Runs the cases exactly as `lab test` does (fresh, sanitized build). A failed
   case or a compile error refuses with `LAB_PROMOTE_CASES_FAILED`; the message
   names the failed count and `error.next_action` is `z23 lab show <root>`.
2. Builds a release image of the same source with the lab's compiler:
   `-std=c23 -O2 -Wall -Wextra -Werror -pedantic -static-pie`, no sanitizers and
   no `-g`. A failed build refuses with `LAB_PROMOTE_BUILD_FAILED`.
3. Runs every case again against that image through the confined runner that
   `plugin call` uses. Any failure refuses with `LAB_PROMOTE_RELEASE_DISAGREES`.
4. Packs the image as an interface 2 plugin through `plugin pack` with the key
   file you name (`name`, `version` and `key` are required; `cap` and `dir` are
   as for `plugin pack`). The key is only read; nothing is generated or moved.

It signs, so it carries the authority of `plugin pack`, and it installs nothing:
the reply's `next` is the install command. Linux only; other hosts refuse with
`LAB_UNSUPPORTED`. Inputs: `file`, `cases`, `name`, `version`, `key`, `cap`,
`dir`, `sanitize`, `timeout_ms`, `mem_mb`. The receipt `zcl.lab_promote.v1`
carries `root` (of the test run), `cases_passed`, `release_command`,
`release_sha3_512`, `name`, `version`, `manifest`, `signature`, `generation`,
`public_key`; the reply's `next` array names `plugin.install`.

Run on r1 (GCC 14.2.0) with a throwaway `HOME`; the publisher key is added with
`plugin publisher`. `upper.c` upper-cases stdin and `cases.json` is

```
[{"name":"lower","stdin":"abc\n","expect_stdout":"ABC\n"},
 {"name":"mixed","stdin":"Hello, z23\n","expect_stdout":"HELLO, Z23\n"}]
```

```
$ z23 plugin keygen ./publisher.key           # prints public_key
$ z23 plugin publisher <64-hex-public-key>        # appends it to ~/.z23/plugins/publisher_keys
$ z23 lab promote upper.c --cases=cases.json --name=upper --version=1.0.0 \
      --key=./publisher.key --dir=./dist
"data":{"schema":"zcl.lab_promote.v1","root":"0bc5665f...c260","cases_passed":2,
 "release_command":"zcc /usr/bin/x86_64-linux-gnu-gcc-14 -std=c23 -O2 -Wall -Wextra -Werror -pedantic -static-pie upper.c -o upper.c.1760126.bin -lm",
 "release_sha3_512":"779654bf...2602","name":"upper","version":"1.0.0",
 "manifest":"./dist/upper.plugin.json","signature":"./dist/upper.plugin.sig",
 "generation":"e5ff7f8e...9242","public_key":"b65cf7c7...8d15"}
$ z23 plugin install --manifest=./dist/upper.plugin.json     # ok, generation e5ff7f8e...9242
$ z23 plugin switch upper e5ff7f8e...9242                    # ok, current e5ff7f8e...9242
$ z23 plugin call upper --stdin='abc
'
"run":{"ran":true,"exit_code":0,"signal":0,...,"stdout":"ABC\n",...}
```

The plugin's stdout `ABC\n` is the first case's `expect_stdout`, and the
`sha3_512` of the `plugin call` reply equals `release_sha3_512`. Without the
`switch`, `plugin call` refuses with `PLUGIN_NO_GENERATION`. Through MCP the leaf is `lab.promote`.

## Measured latency

2026-10-18 on r1 (AMD Ryzen 9 7950X3D, GCC 14.2.0, Linux 6.8.0-139, load
average about 13 from other workers). Smallest of three consecutive runs of
`build/bin/z23-dev lab run`; `fresh` recompiles with a warm compile cache,
`cold` starts from an empty state directory. Times are the receipt's own
`elapsed_us`; the last column is the `time` of the CLI process for a cached
reply, which is node start-up.

| Program | Build | Cold | Fresh | Cached reply | CLI wall, cached |
|---|---|---|---|---|---|
| `hello.c` (6 lines) | sanitizers | 188 ms | 55 ms | 0.14 ms | 25 ms |
| `hello.c` | plain | 115 ms | 45 ms | 0.14 ms | 16 ms |
| `workload.c` (567 lines) | sanitizers | 297 ms | 223 ms | 0.22 ms | 24 ms |
| `workload.c` | plain | 190 ms | 119 ms | 0.23 ms | 14 ms |

Compile dominates; the confined run is 1 to 14 ms. The first run on a cold
host measured 1.2 s for sanitized hello while another worker was building.
