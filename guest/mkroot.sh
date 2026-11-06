#!/bin/bash
# Build guest/root.img: a 32 MB ext2 disk whose /sbin/init is guest/init.c (no
# libc; static, sparc32 Linux user mode).  No root privileges needed: mke2fs -d
# populates it from a staging directory and debugfs adds the /dev/console node.
#   ./mkroot.sh [out.img]
set -e
cd "$(dirname "$0")"
OUT=${1:-root.img}
B=build
mkdir -p $B/root/sbin $B/root/dev $B/root/proc
clang --target=sparc-unknown-linux-gnu -mcpu=v8 -O2 -ffreestanding -fno-builtin \
      -nostdlib -fno-pic -c init.c -o $B/init.o
sparc64-linux-gnu-ld -m elf32_sparc -static -e _start -Ttext=0x10000 -o $B/root/sbin/init $B/init.o
rm -f $OUT
mke2fs -q -t ext2 -b 1024 -d $B/root -L ss10root $OUT 32M
printf "cd /dev\nmknod console c 5 1\n" > $B/debugfs.cmd
debugfs -w -f $B/debugfs.cmd $OUT
echo "built $OUT"
