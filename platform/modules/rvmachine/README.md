# zclassic23/rvmachine

The built-in RISC-V machine: the rvemu hart, the rvplat interrupt controller,
timer, firmware-call handler and serial port, the rvvirtio block and entropy
devices and
the fdt writer composed into one computer that boots a supervisor kernel.

Machine contract v1.7 (everything in v1, plus the points marked 1.1 to 1.7):

* One hart, RV64 IMAFDC, S and U modes, Sv39. There is no firmware image: a
  supervisor ecall stops the engine and the host answers it (base, TIME, IPI,
  RFENCE, HSM, SRST and the legacy calls 0..8, console included). A remote
  fence that selects this hart flushes its whole translation cache, whatever
  range it names; one that selects no hart does nothing.
* Entry: S-mode, satp 0, interrupts off, a0 = 0, a1 = the device tree address,
  pc = 0x80200000. 1.1: scounteren = 7, so user mode may read cycle, time and
  instret without a trap (a kernel that never writes scounteren expects the
  firmware to have done so).
* RAM at 0x80000000, 1 GiB by default. 1.1: the device tree blob sits 2 MiB
  below the end of RAM and never above RAM base + 1 GiB - 2 MiB, because a
  kernel's boot page tables identity-map only the first gigabyte.
* PLIC at 0x0C000000 (31 sources; context 1 is the supervisor external line),
  ns16550 at 0x10000000 on source 10, virtio mmio slots at 0x10001000 to
  0x10008000 on sources 1 to 8. Slot 0 is the block device when a disk is
  given. 1.3: slot 1 (source 2) is the entropy device when the embedder gives
  an entropy source. 1.7: slot 2 (source 3) is a multiport console when named
  byte ports are configured. Every other slot answers as empty, and the device tree
  is the same whichever devices are there. An address nothing answers is an
  access fault.
* 1.7: the embedder can configure one to eight distinct named byte ports and
  a sink that returns the accepted prefix length. Each port holds at most
  4096 host-input bytes and serves at most 4096 bytes per direction per round.
  A short sink result holds the suffix until explicit resume; exhausting a
  port's quantum resumes in the next service round. Polling guests progress
  with interrupts masked, but held work cannot wake a masked waiting hart.
  Accepted bytes contribute to device work once per notify/service round.
  Overaccepting sinks refuse the run as `RVMACHINE_ERR_PORT`, including at
  its final work boundary. Close and device reset discard queued host input
  and held device transmit suffixes and advance the host generation. This
  cannot retract bytes already consumed by the guest: peer replacement
  requires a separate guest protocol binding its session epoch. The consumed
  counter records driver consumption, not an application acknowledgment.
  Without configured ports slot 2 remains absent.
* 1.1: time = retired instructions / 10 + skip, at a 10 MHz timebase. skip is
  the sum of the wfi fast-forwards: a wfi with the timer armed jumps the time
  to the deadline. The time saturates at the top of its 64-bit range instead
  of wrapping. No host clock and no host randomness is read, so two runs
  with the same inputs are identical.
* 1.1: a firmware call is a trap and does not retire. Answered calls are
  counted separately (fw_calls).
* 1.2: the run budget is work = retired instructions + firmware calls + device
  work. Device work is the disk data moved for the guest, read or written,
  and (1.3) the entropy delivered to it: one unit per started 4096 bytes moved
  by each queue notification or service round. A guest can neither spin
  through firmware calls nor make the host copy device data for free. The
  budget is looked at between instruction steps and service rounds, so a run
  passes it by at most one step and one capped round of each device. The
  retired, skip and firmware-call counts of a run are those of v1.1.
* 1.3: the entropy device hands the guest exactly the bytes of the embedder's
  callback, in order, and nothing else: the module reads no host randomness
  and no clock, so a run fed the same bytes repeats exactly. A callback that
  has nothing leaves the request waiting; it is asked again when the guest
  notifies the device or after `rvmachine_entropy_ready`, not on every
  instruction, and a waiting request does not keep a sleeping hart awake.
  Without a callback there is no entropy device and a run is the v1.2 run.
* 1.4: wait stops, off by default. With `wait_stops` in the config the
  machine does not jump time over a timed wfi: `rvmachine_run` returns
  `RVMACHINE_STOP_WAIT` with the timer deadline in the result, having done no
  work, and the embedder moves guest time with `rvmachine_advance_time`, so a
  host loop can sleep while the guest sleeps. The target time must not lie
  before the present nor after the armed deadline; either is refused by name
  and changes nothing. A wait stop is not handed out twice for nothing: a run
  made after one is refused (`RVMACHINE_ERR_WAITING`) until something can
  wake the hart (1.5). A
  timer armed at or before the present is not a wait, and arming a new
  deadline takes a firmware call, so a guest cannot make a host loop turn
  without paying work for every turn. Driven with time advanced exactly to
  each deadline, a run retires the same instructions, reports the same skip
  and guest time and prints the same console as the default mode; the times
  given to `rvmachine_advance_time` are inputs of the run and replay it.
  Without the flag nothing changes: no run returns a wait stop.
  `rvmachine_timer_deadline` and `rvmachine_pending` (console input the
  serial port will take unasked, an entropy request the source can still
  serve, left-over block requests) read the machine in either mode.
* 1.5: a waiting hart is run again only when something can wake it. The test
  is the wfi rule itself, an interrupt both pending and enabled in the hart
  (mip and mie; the global enable plays no part). `rvmachine_pending` reports
  console input as `CONSOLE` only when it ends a wfi now, and as
  `CONSOLE_HELD` when a gate is shut: the external interrupt masked in the
  hart, the port's receive interrupt off, or the port's source held back by
  the interrupt controller. Device requests count only while their driver
  runs the queue. `CONSOLE`, `ENTROPY` and `BLOCK` are
  `RVMACHINE_PENDING_RUNNABLE`: none is set at a wait or idle stop, and a
  run made while one is set acts on it. With wait stops a run after a wait
  or idle stop is refused (`RVMACHINE_ERR_WAITING`, no work) until a call
  makes the hart able to wake or gives a device work; input behind a shut
  gate, time advanced short of the deadline and an entropy signal with
  nothing waiting do not, however often they are repeated. This replaces
  the 1.4 rule that any input or advance allowed a rerun. A timer that has
  passed with its interrupt masked is not a deadline:
  `rvmachine_timer_deadline` and the result report none, a hart reaching wfi
  with it gets the idle stop (one already waiting when it passed stays
  refused), and time may be advanced past it. For a waiting hart, no deadline
  and no runnable flag mean it sleeps until input.
* 1.6: the boot seed, off by default. A FreeBSD kernel seeds its random
  device before the first use only from a module its boot loader preloaded;
  the firmware entry forces an empty loader list and no device tree property
  is read. With a `boot_seed` source in the config, `rvmachine_load_kernel`
  therefore enters an ELF kernel the way that loader does: at the physical
  address of `e_entry`, a0 = the kernel virtual address of a metadata list,
  a1 = 0. Above the image, a page each, it writes a copy of the device tree,
  2048 bytes from the source and the list: the module `kernel` (type
  `elf kernel`: address, size, device tree, end of everything, verbose boot
  flag, boot hart 0) and the module `entropy` (type `boot_entropy_platform`:
  address and size of the seed). The virtual addresses come from the image's
  own segment headers. The source is asked once, last, for exactly 2048
  bytes; no bytes, too few, a failure or a buffer left all zero refuse the
  load by name (`RVMACHINE_ERR_SEED_ABSENT`, `_SHORT`, `_SOURCE`), as do a
  flat image, an `e_entry` outside the file bytes of an executable segment
  or loaded at an odd address, and segments without one common virtual
  offset, or boot metadata that is not word aligned (`RVMACHINE_ERR_ENTRY`),
  and an image that leaves no room
  (`RVMACHINE_ERR_IMAGE_RANGE`). A refused
  load has written nothing to guest memory, and the fetched bytes are wiped
  from host memory either way. `rvmachine_boot_seed_cleared` tells whether
  the guest has since zeroed the seed, as a kernel does once it has taken
  it. Without a source the entry, the registers, the device tree's place
  and every count are exactly as before. The list format is the guest's; it
  lives in `rvmachine_preload.c` and nowhere else.
* Console: the firmware console calls and the serial port write to one sink.
  Every input byte is offered to both the firmware getchar call and the serial
  receive path with its interrupt, so neither reader can starve the other.
* Requests a device left unfinished are continued before every
  instruction step and, while the budget lasts, finished before a wfi may skip
  time or end the run as idle.

The loader takes an ELF64 RISC-V image (segments at their physical addresses
when those start at 0x80200000 and lie in RAM, otherwise relative to the lowest
virtual address) or a flat binary, and refuses an image that ends above 768 MiB
into RAM or reaches the device tree. Every segment is checked before any byte
is written. A machine takes one kernel: a second load is refused, because a
reloaded machine would not be a fresh one.

The module opens no file. A disk is `size` bytes of image behind a caller's
read function, so nothing here can write the image. Guest writes go to an
in-memory copy-on-write overlay of 4 KiB blocks capped at 256 MiB; past the cap
a write to a new block fails and the guest sees an I/O error.

The separate `rvmachine_disk_open_backend` API retains caller-owned read,
write and flush callbacks. It sends admitted ranges directly to that backend,
without an overlay, and reports flush failure to the guest. The caller keeps
the callbacks and context alive until close and quiesces execution before
closing; close neither flushes nor releases the context. This generic storage
interface does not encrypt data or authorize a writable host file.

`rvmachine_run` returns a typed reason: budget, shutdown, reboot, wait (only
with wait stops), idle (wfi with nothing that can wake the hart), fault (with
pc, cause and tval; 1024 steps in a row that trap without retiring are a
fault too) or requested.

A console script (`rvmachine_script_*`) types text when the output ends with a
marker and requests a stop on a final marker. It matches at the instruction
boundary a byte is printed at, so a scripted run repeats exactly.

The sources carry a few `RVMACHINE_POLICY_*` points that the test group
replaces in a mutation twin; a build that defines one without also declaring
itself the twin (`RVMACHINE_TWIN_BUILD`) does not compile.

Proofs: `tests/harness/src/test_rvmachine.c` runs the supervisor guests of
`tests/fixtures/rvmachine` through the machine. The command leaf
`dev app machine boot` (`tools/command/native_dev_machine_boot.c`) is the machine
with files around it; `docs/commons/RISCV_MACHINE.md` shows how to boot a kernel.

Written from the RISC-V privileged, SBI, PLIC, VIRTIO and devicetree
specifications. Depends on base, fdt, rvemu, rvplat and rvvirtio.
