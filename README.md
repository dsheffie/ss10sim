# ss10sim

A functional SPARC V8 full-system simulator for the sun4m SPARCstation 10/20
(SuperSPARC). It is the reference ISS and test bed for the
[superdupersparc](https://github.com/dsheffie/superdupersparc) core. It was split
from indysim/interp_mips, and the history is kept.

Modeled: the SRMMU and IOMMU, the sun4m interrupt controller and timers, the ESCC
serial ports, the M48T08 NVRAM/RTC, and the ESP SCSI controller with its DMA (a
port of qemu 8.2 `esp.c`) driving SCSI-2 disk and CD-ROM targets.

What runs: the real SS-20 OBP 2.25 (to the `ok` prompt, `probe-scsi`, and
`boot disk`/`boot cdrom`), OpenBIOS with a Linux kernel through fw_cfg (boots
to a SCSI root), and the NeXTSTEP 3.3 install CD (to the installer).

## Build

```sh
make
```

Needs boost (program_options, serialization) and capstone.

## Run

```sh
# real OBP, a disk at target 3 and a CD at target 6, typing into ttya
./ss10sim --rom ss10-20-v2.25r-rom --nvram ss20_nvram.bin --ram 256 \
  --scsi-disk 3:disk.img --scsi-cdrom 6:cd.iso \
  --console-input keys.txt --console-input-at 5900000000

# OpenBIOS + Linux
./ss10sim --rom openbios-sparc32 --kernel vmlinux --append "root=/dev/sda rw" \
  --scsi-disk 0:guest/root.img
```

Other options: `--checkpoint-at`/`--checkpoint-out`/`--restore`, `-m` (the
instruction limit), and `--trace`/`--pctrace`. See `./ss10sim --help` for the
full list. The Sun ROM is proprietary and is not in this repo.

`guest/` builds test images: `mkroot.sh` makes an ext2 Linux root, and
`mksunboot.py` makes a Sun-labelled disk with an a.out boot block for OBP.
