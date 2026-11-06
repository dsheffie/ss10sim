#!/usr/bin/env python3
"""Build guest/sunboot.img: a 32 MB disk with a Sun (VTOC) disk label and
guest/bootblk.S as the a.out boot block in sectors 1-15, for testing the real
OBP's "boot disk" against ss10sim's ESP and SCSI disk.
   ./mksunboot.py [out.img]"""
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'sunboot.img')
B = os.path.join(HERE, 'build')
os.makedirs(B, exist_ok=True)

NSECT, NTRKS = 63, 16
SIZE = 32 << 20
NBLK = SIZE // 512
NCYL = NBLK // (NSECT * NTRKS)
LOAD = 0x4000

# the boot block: assembled, linked at 0x4000, as a raw image
# GNU as (clang's integrated assembler cannot pad a text section with data)
subprocess.check_call(['sparc64-linux-gnu-as', '-32', '-Av8', os.path.join(HERE, 'bootblk.S'),
                       '-o', os.path.join(B, 'bootblk.o')])
subprocess.check_call(['sparc64-linux-gnu-ld', '-m', 'elf32_sparc', '-static', '-e', '_start',
                       '-Ttext=0x%x' % LOAD, '-o', os.path.join(B, 'bootblk.elf'),
                       os.path.join(B, 'bootblk.o')])
subprocess.check_call(['sparc64-linux-gnu-objcopy', '-O', 'binary', '-j', '.text',
                       os.path.join(B, 'bootblk.elf'), os.path.join(B, 'bootblk.bin')])
text = open(os.path.join(B, 'bootblk.bin'), 'rb').read()
text += b'\0' * (-len(text) % 8)
# a.out header (struct exec): sparc OMAGIC 0x01030107, text/data/bss/syms
# sizes, the entry, relocation sizes
aout = struct.pack('>8I', 0x01030107, len(text), 0, 0, 0, LOAD, 0, 0) + text
assert len(aout) <= 15 * 512, 'boot block too big'

# the Sun disk label (Linux block/partitions/sun.c struct sun_disklabel)
lab = bytearray(512)
info = b'ss10sim boot test disk cyl %d alt 0 hd %d sec %d' % (NCYL, NTRKS, NSECT)
lab[0:len(info)] = info
struct.pack_into('>I', lab, 128, 1)                 # vtoc version
lab[132:140] = b'ss10boot'                          # volume
struct.pack_into('>H', lab, 140, 8)                 # nparts
for i, tag in enumerate([2, 0, 5, 0, 0, 0, 0, 0]):  # a = root, c = backup (whole disk)
    struct.pack_into('>HH', lab, 142 + 4 * i, tag, 0x01 if tag == 5 else 0)
struct.pack_into('>I', lab, 188, 0x600DDEEE)        # vtoc sanity
struct.pack_into('>HHHHHHHHHH', lab, 420, 5400, NCYL, 0, 0, 0, 1, NCYL, 0, NTRKS, NSECT)
nblk = NCYL * NTRKS * NSECT
for i, (cyl, n) in enumerate([(0, nblk), (0, 0), (0, nblk)]):
    struct.pack_into('>II', lab, 444 + 8 * i, cyl, n)
struct.pack_into('>H', lab, 508, 0xDABE)
csum = 0
for i in range(0, 510, 2):
    csum ^= struct.unpack_from('>H', lab, i)[0]
struct.pack_into('>H', lab, 510, csum)

with open(OUT, 'wb') as f:
    f.write(lab)
    f.write(aout)
    f.truncate(SIZE)
print('built %s: %d cylinders, boot block %d bytes' % (OUT, NCYL, len(aout)))
