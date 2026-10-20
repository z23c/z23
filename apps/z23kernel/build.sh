#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Inspect the bounded RV64 flat image before publishing its identity.
set -euo pipefail
source_dir=$1
output_dir=$2
: "${Z23KERNEL_CC:=clang}" "${Z23KERNEL_LD:=ld.lld}" "${Z23KERNEL_OBJCOPY:=llvm-objcopy}"
: "${Z23KERNEL_READELF:=readelf}" "${Z23KERNEL_NM:=nm}"
mkdir -p "$output_dir"
source_dir=$(cd "$source_dir" && pwd)
output_dir=$(cd "$output_dir" && pwd)
bin_dir=$(cd "$3" && pwd)
source "$source_dir/../../tools/dev/build-epoch-lock-wait.sh"
exec 9>"$output_dir/build.lock"
z23_build_epoch_flock_bounded z23kernel 9 "$output_dir/build.lock" kernel-output
cd "$output_dir"
"$Z23KERNEL_CC" --target=riscv64-unknown-elf -std=c23 -march=rv64ima_zicsr -mabi=lp64 -mcmodel=medany -msmall-data-limit=0 -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -mno-relax -fno-unwind-tables -fno-asynchronous-unwind-tables -O1 -Wall -Wextra -Werror -pedantic -fstack-usage -c "$source_dir/main.c" -o main.o
"$Z23KERNEL_CC" --target=riscv64-unknown-elf -march=rv64ima_zicsr -mabi=lp64 -mcmodel=medany -mno-relax -c "$source_dir/entry.S" -o entry.o
"$Z23KERNEL_LD" -m elf64lriscv -static --build-id=none --no-relax -e _start --image-base 0x80000000 --Ttext=0x80200000 --section-start=.rodata=0x80201000 -o kernel.elf entry.o main.o
"$Z23KERNEL_READELF" -h -l -SW -s -d kernel.elf > elf-review.log
section_headers=$("$Z23KERNEL_READELF" -SW kernel.elf)
program_headers=$("$Z23KERNEL_READELF" -lW kernel.elf)
# GNU and LLVM readelf use different prose for an absent dynamic section.
# Inspect ELF structure and reject empty or unrecognized inspection output.
grep -q '^Section Headers:' <<<"$section_headers"
grep -q '^Program Headers:' <<<"$program_headers"
test "$(awk '/^[[:space:]]*\[/ {for (i=1;i<=NF;i++) if ($i == "DYNAMIC") n++} END {print n+0}' <<<"$section_headers")" -eq 0
test "$(awk '$1 == "DYNAMIC" || $1 == "INTERP" {n++} END {print n+0}' <<<"$program_headers")" -eq 0
"$Z23KERNEL_OBJCOPY" -O binary --remove-section=.eh_frame_hdr kernel.elf kernel.bin
scratch=$(mktemp -d "${TMPDIR:-$output_dir}/z23kernel-inspect.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
"$Z23KERNEL_NM" -P --defined-only kernel.elf > symbols.log
symbol() { awk -v key="$1" '$1 == key {print "0x" $3}' symbols.log; }
start=$(symbol _start)
probe=$(symbol illegal_probe)
resume=$(symbol illegal_resume)
bss=$(symbol __bss_start)
end=$(symbol _end)
bottom=$(symbol stack_bottom)
top=$(symbol stack_top)
test "$((start))" -eq "$((0x80200000))"
test "$((resume - probe))" -eq 4
test "$((top % 16))" -eq 0
test "$((top - bottom))" -eq 16384
test "$((bss))" -ge "$((0x80200000))"
test "$((end))" -le "$((0x80300000))"
"$Z23KERNEL_READELF" -SW kernel.elf | awk '{
 for(i=1;i<=NF;i++) if($i ~ /^\./ && $(i+6) ~ /A/) print $i, $(i+1), "0x"$(i+2), "0x"$(i+4)
}' > sections.log
grep -q "^\.text PROGBITS " sections.log
grep -q "^\.bss NOBITS " sections.log
grep -q "^\.rodata PROGBITS " sections.log
while read -r name type address size; do
 test "$name" != .eh_frame_hdr || continue
 test "$((address))" -ge "$((start))"
 test "$((address + size))" -le "$((end))"
 case "$type" in
 NOBITS) ;;
 PROGBITS)
  "$Z23KERNEL_OBJCOPY" --dump-section "$name=$scratch/section" kernel.elf "$scratch/elf-copy"
  dd if=kernel.bin of="$scratch/flat" bs=1 skip="$((address - start))" count="$((size))" 2>/dev/null
  cmp "$scratch/section" "$scratch/flat" ;;
 *) printf 'z23kernel: unsupported allocated section %s\n' "$name" >&2; exit 1 ;;
 esac
done < sections.log
test "$(wc -c < kernel.bin)" -lt 65536
hash=$(sha256sum kernel.bin | awk '{print $1}')
printf '%s %x %x %x\n' "$hash" "$((probe-start))" "$((resume-start))" "$((end-start))" > kernel.identity
cp kernel.bin "$bin_dir/z23kernel.bin.tmp.$$"
cp kernel.identity "$bin_dir/z23kernel.identity.tmp.$$"
mv "$bin_dir/z23kernel.bin.tmp.$$" "$bin_dir/z23kernel.bin"
mv "$bin_dir/z23kernel.identity.tmp.$$" "$bin_dir/z23kernel.identity"
