#!/bin/bash
# Build guest/root.img: a 32 MB ext2 disk whose /sbin/init is guest/init.c (no
# libc; static, sparc32 Linux user mode).  No root privileges needed: mke2fs -d
# populates it from a staging directory and debugfs adds the /dev/console node.
#   ./mkroot.sh [out.img [workload ...]]
# With workloads (static sparc32 Linux executables, e.g. the csmith *_u.elf),
# they go in as /bin/w0000, /bin/w0001, ... and /sbin/init is workinit.c, which
# runs them in turn forever: a busy userland for co-sim sampling.
set -e
cd "$(dirname "$0")"
OUT=${1:-root.img}
shift || true
B=build
rm -rf $B/root
mkdir -p $B/root/sbin $B/root/dev $B/root/proc $B/root/bin
INIT=init
if [ $# -gt 0 ]; then
  INIT=workinit
  k=0
  for w in "$@"; do
    cp "$w" $(printf "$B/root/bin/w%04d" $k)
    k=$((k + 1))
  done
fi
clang --target=sparc-unknown-linux-gnu -mcpu=v8 -O2 -ffreestanding -fno-builtin \
      -nostdlib -fno-pic -c $INIT.c -o $B/$INIT.o
sparc64-linux-gnu-ld -m elf32_sparc -static -e _start -Ttext=0x10000 -o $B/root/sbin/init $B/$INIT.o
SIZE=$(( ( $(du -sk $B/root | cut -f1) / 1024 + 32 ) ))M
rm -f $OUT
mke2fs -q -t ext2 -b 1024 -d $B/root -L ss10root $OUT $SIZE
printf "cd /dev\nmknod console c 5 1\n" > $B/debugfs.cmd
debugfs -w -f $B/debugfs.cmd $OUT
echo "built $OUT"
