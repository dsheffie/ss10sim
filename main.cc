#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <boost/program_options.hpp>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

#include "interpret.hh"
#include "sun4m.hh"
#include "loadelf.hh"
#include "disassemble.hh"
#include "helper.hh"
#include "ckpt.hh"
#include "globals.hh"
#include "display.hh"
#include "keymap.hh"

/* Standalone SPARC V8 ISS driver: run an ELF, optionally under Linux user-mode
 * syscall/window emulation (--user) so the same static binary can be diffed
 * against qemu-sparc. */

namespace globals {
  bool enClockFuncts = false;
  uint64_t cycle = 0;
  bool trace_retirement = false;
  bool trace_fp = false;
  bool report_syscalls = false;
};

/* --scsi-disk / --scsi-cdrom: "[ID:]image" targets on the ESP's bus; without an
 * ID the next free one from first_id up (the initiator, the ESP, is ID 7) */
static bool attach_scsi(sun4m_t *m, const std::vector<std::string> &specs, scsi_dev_t::type_t t,
			uint32_t first_id, uint32_t cdrom_bs = 2048) {
  uint32_t next = first_id;
  for(const std::string &spec : specs) {
    uint32_t id;
    std::string path = spec;
    const size_t colon = spec.find(':');
    if(colon == 1 and spec[0] >= '0' and spec[0] <= '6') {
      id = spec[0] - '0';
      path = spec.substr(2);
    }
    else {
      while(next < 7 and m->scsi[next] != nullptr) {
	next++;
      }
      id = next;
    }
    if(id >= 7 or m->scsi[id] != nullptr) {
      fprintf(stderr, "scsi: no free target ID for '%s'\n", spec.c_str());
      return false;
    }
    scsi_dev_t *d = new scsi_dev_t(t, path);
    if(not d->ok()) {
      delete d;
      return false;
    }
    if(t == scsi_dev_t::type_t::cdrom) {
      d->power_on_bs = cdrom_bs;
      d->bs = cdrom_bs;
    }
    m->scsi[id] = d;
    fprintf(stderr, "scsi: target %u: %s\n", id, path.c_str());
  }
  return true;
}

/* qemu sun4m_hw_init's fw_cfg items and -kernel load: the kernel's segments go
 * to RAM at vaddr - 0xf0000000 (KERNEL_LOAD_ADDR 0x4000 is where its text
 * lands), the command line to 0x7ff000.  The values match qemu -M SS-20 with
 * one CPU and -nographic. */
static bool setup_fw_cfg(state_t *s, const std::string &kernel, const std::string &append,
			 const std::string &initrd, uint32_t INITRD_LOAD_ADDR) {
  static const uint32_t KERNEL_LOAD_ADDR = 0x4000, CMDLINE_ADDR = 0x7ff000;
  static const uint16_t FW_CFG_SIGNATURE = 0x00, FW_CFG_ID = 0x01, FW_CFG_UUID = 0x02, FW_CFG_RAM_SIZE = 0x03,
    FW_CFG_NOGRAPHIC = 0x04, FW_CFG_NB_CPUS = 0x05, FW_CFG_MACHINE_ID = 0x06, FW_CFG_KERNEL_ADDR = 0x07,
    FW_CFG_KERNEL_SIZE = 0x08, FW_CFG_KERNEL_CMDLINE = 0x09, FW_CFG_INITRD_ADDR = 0x0a, FW_CFG_INITRD_SIZE = 0x0b,
    FW_CFG_BOOT_DEVICE = 0x0c, FW_CFG_BOOT_MENU = 0x0e, FW_CFG_MAX_CPUS = 0x0f, FW_CFG_CMDLINE_SIZE = 0x14,
    FW_CFG_CMDLINE_DATA = 0x15, FW_CFG_SUN4M_DEPTH = 0x8000, FW_CFG_SUN4M_WIDTH = 0x8001, FW_CFG_SUN4M_HEIGHT = 0x8002;
  static const uint16_t SS20_MACHINE_ID = 65;
  fw_cfg_t &f = s->sun4m->fw_cfg;
  uint8_t uuid[16] = {0};
  f.add_bytes(FW_CFG_SIGNATURE, "QEMU", 4);
  f.add_bytes(FW_CFG_UUID, uuid, sizeof(uuid));
  f.add_i16(FW_CFG_NOGRAPHIC, 1);
  f.add_i16(FW_CFG_BOOT_MENU, 0);
  f.add_i32(FW_CFG_ID, 1);                         /* traditional interface, no DMA */
  f.add_i16(FW_CFG_NB_CPUS, 1);
  f.add_i16(FW_CFG_MAX_CPUS, 1);
  f.add_i64(FW_CFG_RAM_SIZE, s->ram_size);
  f.add_i16(FW_CFG_MACHINE_ID, SS20_MACHINE_ID);
  f.add_i16(FW_CFG_SUN4M_DEPTH, 8);
  f.add_i16(FW_CFG_SUN4M_WIDTH, 1024);
  f.add_i16(FW_CFG_SUN4M_HEIGHT, 768);
  uint64_t kernel_size = 0;
  if(not kernel.empty()) {
    uint32_t entry = 0;
    auto seg = [&](uint32_t vaddr, const uint8_t *data, uint32_t filesz, uint32_t memsz) {
      uint32_t pa = vaddr - 0xf0000000u;
      for(uint32_t i = 0; i < memsz; i++) {
	s->mem.set<uint8_t>(pa + i, (i < filesz) ? data[i] : 0);
      }
    };
    if(not for_each_elf_segment(kernel.c_str(), seg, &entry, &kernel_size)) {
      fprintf(stderr, "ss10sim: %s is not a SPARC ELF kernel\n", kernel.c_str());
      return false;
    }
    fprintf(stderr, "ss10sim: kernel %s, %llu bytes, entry 0x%x\n", kernel.c_str(),
	    static_cast<unsigned long long>(kernel_size), entry);
  }
  f.add_i32(FW_CFG_KERNEL_ADDR, KERNEL_LOAD_ADDR);
  f.add_i32(FW_CFG_KERNEL_SIZE, static_cast<uint32_t>(kernel_size));
  if(not append.empty()) {
    std::string c = append.substr(0, 4095);    /* pstrcpy into one page */
    for(size_t i = 0; i <= c.size(); i++) {
      s->mem.set<uint8_t>(CMDLINE_ADDR + i, (i < c.size()) ? static_cast<uint8_t>(c[i]) : 0);
    }
    f.add_i32(FW_CFG_KERNEL_CMDLINE, CMDLINE_ADDR);
    f.add_bytes(FW_CFG_CMDLINE_DATA, append.c_str(), append.size() + 1);
    f.add_i32(FW_CFG_CMDLINE_SIZE, static_cast<uint32_t>(append.size() + 1));
  }
  else {
    f.add_i32(FW_CFG_KERNEL_CMDLINE, 0);
    f.add_i32(FW_CFG_CMDLINE_SIZE, 0);
  }
  /* --initrd: as qemu sun4m_hw_init, the image goes to RAM at INITRD_LOAD_ADDR (qemu's
   * 0x800000 unless --initrd-addr; sparc32 Linux allocates its early page tables
   * bottom-up just above a reserved initrd, which must stay inside the boot-time
   * mapping, so a big initrd goes high in lowmem instead) and
   * its address and size are patched into the kernel's "HdrS" boot header
   * (head_32.S: sparc_ramdisk_image at +16, sparc_ramdisk_size at +20), found in
   * the first 64 pages of the loaded kernel */
  uint32_t initrd_size = 0;
  if(not initrd.empty()) {
    FILE *fp = fopen(initrd.c_str(), "rb");
    if(fp == nullptr) {
      fprintf(stderr, "ss10sim: cannot open initrd %s\n", initrd.c_str());
      return false;
    }
    std::vector<uint8_t> buf;
    uint8_t chunk[65536];
    size_t n;
    while((n = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
      buf.insert(buf.end(), chunk, chunk + n);
    }
    fclose(fp);
    initrd_size = static_cast<uint32_t>(buf.size());
    if(KERNEL_LOAD_ADDR + kernel_size > INITRD_LOAD_ADDR or INITRD_LOAD_ADDR + initrd_size > s->ram_size) {
      fprintf(stderr, "ss10sim: initrd %s (%u bytes) does not fit at 0x%x\n", initrd.c_str(), initrd_size,
	      INITRD_LOAD_ADDR);
      return false;
    }
    for(uint32_t i = 0; i < initrd_size; i++) {
      s->mem.set<uint8_t>(INITRD_LOAD_ADDR + i, buf[i]);
    }
    bool patched = false;
    for(uint32_t i = 0; i < 64 * 4096; i += 4096) {
      const uint32_t pa = KERNEL_LOAD_ADDR + i;
      const uint32_t w = (static_cast<uint32_t>(s->mem.get<uint8_t>(pa)) << 24) |
	(static_cast<uint32_t>(s->mem.get<uint8_t>(pa + 1)) << 16) |
	(static_cast<uint32_t>(s->mem.get<uint8_t>(pa + 2)) << 8) | s->mem.get<uint8_t>(pa + 3);
      if(w == 0x48647253u) {                       /* "HdrS" */
	for(uint32_t k = 0; k < 4; k++) {
	  s->mem.set<uint8_t>(pa + 16 + k, static_cast<uint8_t>(INITRD_LOAD_ADDR >> (24 - 8 * k)));
	  s->mem.set<uint8_t>(pa + 20 + k, static_cast<uint8_t>(initrd_size >> (24 - 8 * k)));
	}
	patched = true;
	break;
      }
    }
    if(not patched) {
      fprintf(stderr, "ss10sim: no HdrS header in the kernel's first 64 pages: initrd not passed\n");
      return false;
    }
    fprintf(stderr, "ss10sim: initrd %s, %u bytes at 0x%x\n", initrd.c_str(), initrd_size, INITRD_LOAD_ADDR);
  }
  /* OpenBIOS is told no initrd: it maps one page by page into its own small heap and
   * runs out ("out of malloc memory") on a large one; Linux needs only HdrS */
  f.add_i32(FW_CFG_INITRD_ADDR, INITRD_LOAD_ADDR);
  f.add_i32(FW_CFG_INITRD_SIZE, 0);
  f.add_i16(FW_CFG_BOOT_DEVICE, 'c');
  return true;
}

/* Would qemu end the TB holding insn by returning to its main loop (rather than
 * jumping straight to the next TB)?  qemu sparc translate.c: wr %psr
 * (DISAS_EXIT), rett and alternate-space stores/ldstub through a helper ASI
 * (dynamic npc).  Only used to mirror qemu's -icount exec log. */
static bool qemu_tb_exits(uint32_t insn) {
  if((insn >> 30) == 2) {
    uint32_t op3 = (insn >> 19) & 0x3f;
    return op3 == 0x31 or op3 == 0x39;          /* wr %psr, rett */
  }
  if((insn >> 30) == 3) {
    uint32_t op3 = (insn >> 19) & 0x3f;
    uint32_t asi = (insn >> 5) & 0xff;
    bool alt_store = (op3 >= 0x14 and op3 <= 0x17) or op3 == 0x1d;
    bool direct = asi == 0xa or asi == 0xb or asi == 0x20 or asi == 0x1c or asi == 0x17 or asi == 0x1f;
    return alt_store and not ((insn >> 13) & 1) and not direct;
  }
  return false;
}

/* sun4m system reset (qemu: sparc_cpu_reset_hold + every device's reset): RAM,
 * the PROM and NVRAM survive.  The CPU clears its registers, PSR (S = PS = 1,
 * ET = EF = 0, PIL 0), FSR, FP registers and TBR, sets WIM = 1, restarts at
 * PC 0 and re-enters boot mode with the MMU off; the other MMU registers keep
 * their values.  icnt (time) keeps counting. */
static void system_reset(state_t *s) {
  memset(s->r, 0, sizeof(s->r));
  memset(s->f, 0, sizeof(s->f));
  memset(s->asr, 0, sizeof(s->asr));
  s->icc_n = s->icc_z = s->icc_v = s->icc_c = false;
  s->ef = false;
  s->set_s(true);
  s->ps = true;
  s->et = false;
  s->pil = 0;
  s->cwp = 0;
  s->wim = 1;
  s->tbr = 0;
  s->y = 0;
  s->fsr = 0;
  s->fq_addr = s->fq_insn = 0;
  /* a module reset: the control register to its reset value (and boot mode),
   * not just E/NF cleared as qemu does -- a real reset turns the caches,
   * snooping and cacheable table walks off too, and an RTL core that kept
   * them (superdupersparc mmu.sv) walked stale page tables in OBP after a
   * reboot.  Context and table pointer are kept. */
  s->mmu_ctrl = MCR_RESET | MCR_BMODE;
  mmu_tlb_flush();
  s->pc = 0;
  s->npc = 4;
  s->error_mode = false;
  s->sun4m->reset_devices(s->sun4m->now_ns(s));
  s->sun4m->update_irqs(s);
}

int main(int argc, char *argv[]) {
  namespace po = boost::program_options;
  std::string filename, rom, nvram, pctrace;
  uint32_t ram_mb = 256;
  uint32_t icount_shift = 4;
  uint64_t trace_from = ~0ULL;
  int64_t rtc_base = 1767225600;
  uint64_t ckpt_icnt = ~0ULL, ckpt_exec = ~0ULL;
  std::string ckpt_pc_s, ckpt_out = "ss10sim.ckpt", restore;
  std::string kernel, append, initrd;
  std::string initrd_addr_s = "0x800000";
  std::vector<std::string> scsi_disks, scsi_cdroms;
  std::vector<std::string> console_inputs;
  std::vector<uint64_t> console_input_ats;
  uint64_t max_icnt = ~0ULL;
  std::string tcx_rom, fb_png, kbd_input;
  uint64_t kbd_input_at = 0;
  bool no_kbd = false;
  bool no_fpu = false;
  uint64_t dma_race_snoop_n = 0, dma_race_copy_n = 4;
  bool dma_race_apply = false;
  uint64_t scsi_cmd_us = 250;
  bool no_esp_timing = false;
  std::string esp_irq_at_pc_s;
  std::string watch_pa_s;
  bool vram_map_log = false;
  uint64_t watch_len = 16;
  uint32_t cdrom_bs = 2048;
  uint64_t fb_png_every = 0;
  bool sdl = false, cg14 = false, console_icount = false;
  uint32_t cg14_depth = 0;
  bool user = false, trace = false, dump = false, with_sun4m = false;
  try {
    po::options_description desc("Options");
    desc.add_options()
      ("help", "print help")
      ("file,f", po::value<std::string>(&filename), "sparc elf binary")
      ("rom,r", po::value<std::string>(&rom), "sun4m (SS-20) boot prom image: reset into it instead of an elf")
      ("ram", po::value<uint32_t>(&ram_mb), "sun4m RAM size in MB (with --rom)")
      ("icount-shift", po::value<uint32_t>(&icount_shift), "sun4m time: 2^N ns per instruction (qemu -icount shift=N; default 4)")
      ("rtc-base", po::value<int64_t>(&rtc_base), "sun4m RTC at time 0, seconds since the epoch (default 2026-01-01T00:00:00 UTC; qemu -rtc base=...,clock=vm)")
      ("nvram", po::value<std::string>(&nvram), "sun4m M48T08 nvram image (with --rom)")
      ("sun4m", po::bool_switch(&with_sun4m), "run the elf with the sun4m devices attached (RAM = --ram)")
      ("pctrace", po::value<std::string>(&pctrace), "write every executed pc (hex, one per line) to this file")
      ("maxicnt,m", po::value<uint64_t>(&max_icnt), "max instructions to execute")
      ("user,u", po::bool_switch(&user), "linux user-mode emulation (syscalls + window spill/fill)")
      ("trace,t", po::bool_switch(&trace), "print every executed instruction")
      ("trace-from", po::value<uint64_t>(&trace_from), "print every executed instruction from this icnt on")
      ("kernel", po::value<std::string>(&kernel), "with --rom openbios-sparc32: a Linux vmlinux, booted through fw_cfg (qemu -kernel)")
      ("append", po::value<std::string>(&append), "with --kernel: the kernel command line (qemu -append)")
      ("initrd", po::value<std::string>(&initrd), "with --kernel: an initrd / initramfs image, loaded at PA 0x800000 (qemu -initrd)")
      ("initrd-addr", po::value<std::string>(&initrd_addr_s),
       "with --initrd: load it at this PA instead (a big initrd: high in lowmem, e.g. 0x4000000)")
      ("scsi-disk", po::value<std::vector<std::string>>(&scsi_disks)->composing(),
       "[ID:]image: a SCSI disk on the ESP (default ID 0, then 1, ...; written in place)")
      ("cdrom-bs", po::value<uint32_t>(&cdrom_bs), "CD-ROM block size at power-on: 2048, or 512 as Sun's drives (Solaris 2.5.1)")
      ("scsi-cdrom", po::value<std::vector<std::string>>(&scsi_cdroms)->composing(),
       "[ID:]image: a SCSI CD-ROM on the ESP (default ID 6, as an SS-20's)")
      ("console-input", po::value<std::vector<std::string>>(&console_inputs)->composing(),
       "file (or - for stdin) typed into ttya, one byte whenever its receiver is empty; \\n is sent as \\r.  "
       "Repeatable: each file starts once the previous one is used up")
      ("console-input-at", po::value<std::vector<uint64_t>>(&console_input_ats)->composing(),
       "with --console-input: start typing at this icount (so start-up code cannot swallow it); "
       "the Nth one goes with the Nth --console-input")
      ("tcx", po::value<std::string>(&tcx_rom)->implicit_value("/usr/share/qemu/QEMU,tcx.bin"),
       "a TCX framebuffer (1024x768x8) in SBus slot 2, with this FCode PROM (default qemu's QEMU,tcx.bin)")
      ("console-icount", po::bool_switch(&console_icount),
       "also write each ttya line to stderr with the icount it ended at")
      ("cg14", po::bool_switch(&cg14), "a CG14 (SX) framebuffer on an 8 MB VSIMM in slot 3 (what NeXTSTEP drives on an SS-20)")
      ("cg14-depth", po::value<uint32_t>(&cg14_depth),
       "with --cg14: show the VRAM as 8 or 32 (XBGR) bits per pixel whatever the MCR pixel mode says "
       "(NeXTSTEP's WindowServer draws 32 with MCR in 8-bit mode)")
      ("sdl", po::bool_switch(&sdl), "with --tcx: show the screen in an SDL window (closing it stops the run)")
      ("kbd-input", po::value<std::string>(&kbd_input),
       "with --tcx/--cg14: a file typed on the Sun keyboard (ASCII, US layout; \\n is Return, ^A-^Z are Control+letter)")
      ("dma-race", po::value<uint64_t>(&dma_race_snoop_n),
       "model Kodiak's snoop / memcpy / snoop DMA write with this many instructions per line snoop, and report "
       "lines the core fills stale and dirties inside the window (interpret.cc)")
      ("dma-race-copy", po::value<uint64_t>(&dma_race_copy_n), "with --dma-race: instructions per 16-byte line of the memcpy (default 4)")
      ("vram-map-log", po::bool_switch(&vram_map_log), "print each distinct CPU translation onto the CG14 (VRAM/registers) once, with its PTE's C bit")
      ("watch-pa", po::value<std::string>(&watch_pa_s), "log every CPU access to this physical address range (hex), with pc and icnt")
      ("watch-len", po::value<uint64_t>(&watch_len), "with --watch-pa: bytes to watch (default 16)")
      ("scsi-cmd-us", po::value<uint64_t>(&scsi_cmd_us), "a SCSI target's command overhead in us (default 250): the ESP's interrupt waits for it")
      ("no-esp-timing", po::bool_switch(&no_esp_timing), "the ESP interrupts as soon as the model finishes a command (qemu's behaviour)")
      ("esp-irq-at-pc", po::value<std::string>(&esp_irq_at_pc_s), "dbg: hex pc; its store to the --watch-pa range releases a held ESP interrupt at once")
      ("dma-race-apply", po::bool_switch(&dma_race_apply), "with --dma-race: write the old bytes back over a clobbered line, as the board would")
      ("no-fpu", po::bool_switch(&no_fpu), "no FPU: PSR.EF reads 0, FP instructions take fp_disabled (a NO_FPU core)")
      ("no-kbd", po::bool_switch(&no_kbd), "with --tcx or --cg14: no keyboard (OBP falls back to ttya, like qemu -nographic)")
      ("kbd-input-at", po::value<uint64_t>(&kbd_input_at), "with --kbd-input: start typing at this icount")
      ("fb-png", po::value<std::string>(&fb_png), "with --tcx: write the screen to this PNG at exit")
      ("fb-png-every", po::value<uint64_t>(&fb_png_every), "with --fb-png: also every this many instructions (a %llu in the --fb-png name numbers them by icount)")
      ("checkpoint-at", po::value<uint64_t>(&ckpt_icnt), "write a checkpoint (--checkpoint-out) when icnt reaches this, then exit")
      ("checkpoint-after-exec", po::value<uint64_t>(&ckpt_exec),
       "write a checkpoint once this many instructions have executed since start/restore (halted time, "
       "which advances icnt, does not count: the point lands in real work), then exit")
      ("checkpoint-at-pc", po::value<std::string>(&ckpt_pc_s), "write a checkpoint the first time this pc is about to execute, then exit")
      ("checkpoint-out", po::value<std::string>(&ckpt_out), "checkpoint file to write (default ss10sim.ckpt)")
      ("restore", po::value<std::string>(&restore), "start from a checkpoint (after the --rom/--kernel setup it replaces)")
      ("dump,d", po::bool_switch(&dump), "dump register state at exit");
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);
    if(vm.count("help") or (filename.empty() and rom.empty())) {
      std::cout << desc << "\n";
      return 1;
    }
  }
  catch(po::error &e) {
    std::cerr << "command line error : " << e.what() << "\n";
    return 1;
  }

  sparse_mem mem;
  state_t *s = new state_t(mem);
  s->user_emu = user;
  s->no_fpu = no_fpu;
  initState(s);
  s->ef = s->ef and not no_fpu;
  if(not rom.empty()) {
    /* sun4m power-on: PC 0 / nPC 4 in Viking boot mode; WIM=1 and PS=1 as qemu
     * resets them (architecturally undefined), so traces line up */
    s->sun4m = new sun4m_t();
    s->sun4m->ns_shift = icount_shift;
    s->sun4m->rtc_base = rtc_base;
    if(not s->sun4m->load_prom(rom.c_str())) {
      return 1;
    }
    if(not nvram.empty() and not s->sun4m->load_nvram(nvram.c_str())) {
      return 1;
    }
    if(not tcx_rom.empty()) {
      s->sun4m->tcx = new tcx_t();
      if(not s->sun4m->tcx->load_rom(tcx_rom)) {
	fprintf(stderr, "ss10sim: cannot read the TCX FCode %s\n", tcx_rom.c_str());
	return 1;
      }
    }
    if(cg14) {
      if(cg14_depth != 0 and cg14_depth != 8 and cg14_depth != 32) {
	fprintf(stderr, "ss10sim: --cg14-depth must be 8 or 32\n");
	return 1;
      }
      s->sun4m->cg14 = new cg14_t();
      s->sun4m->cg14->depth_override = cg14_depth;
    }
    if(s->sun4m->tcx or s->sun4m->cg14) {
      /* a console with a screen has a keyboard (qemu without -nographic);
       * --no-kbd is qemu -nographic: OBP still probes and maps the framebuffer
       * but falls back to ttya (Solaris 2.5.1 needs that framebuffer mapping:
       * it leaves the hole its phys_avail check looks for) */
      s->sun4m->have_kbd = not no_kbd;
      s->sun4m->reset_devices(0);  /* power-on state again, with the framebuffer and the keyboard */
    }
    if(cdrom_bs != 512 and cdrom_bs != 2048) {
      fprintf(stderr, "ss10sim: --cdrom-bs must be 512 or 2048\n");
      return 1;
    }
    if(not attach_scsi(s->sun4m, scsi_disks, scsi_dev_t::type_t::disk, 0) or
       not attach_scsi(s->sun4m, scsi_cdroms, scsi_dev_t::type_t::cdrom, 6, cdrom_bs)) {
      return 1;
    }
    s->ram_size = static_cast<uint64_t>(ram_mb) << 20;
    if(not setup_fw_cfg(s, kernel, append, initrd, static_cast<uint32_t>(strtoul(initrd_addr_s.c_str(), nullptr, 0)))) {
      return 1;
    }
    s->mmu_ctrl |= MCR_BMODE;
    s->pc = 0;
    s->npc = 4;
    s->wim = 1;
    s->ps = true;
  }
  else {
    load_elf(filename.c_str(), s);
    if(with_sun4m) {
      s->sun4m = new sun4m_t();
      s->ram_size = static_cast<uint64_t>(ram_mb) << 20;
    }
  }
  if(not restore.empty() and not load_checkpoint(restore.c_str(), s)) {
    return 1;
  }
  s->ef = s->ef and not no_fpu;
  /* the decoded-instruction cache trusts a filled slot: a restored RAM image
   * and every DMA write into RAM empty the slots they cover */
  predecode_flush_all();
  s->uicnt_base = 0;             /* the user icount counts from here (a restore set S directly) */
  s->u_enter = s->icnt;
  vram_map_log_config(vram_map_log);
  if(s->sun4m) {
    s->sun4m->dma_hook = predecode_dma_write;
    s->sun4m->esp_cmd_ns = scsi_cmd_us * 1000;
    s->sun4m->esp_timing = not no_esp_timing;
    if(not watch_pa_s.empty()) {
      watch_config(std::stoull(watch_pa_s, nullptr, 16), watch_len);
      if(not esp_irq_at_pc_s.empty()) {
        watch_irq_at_pc(static_cast<uint32_t>(std::stoul(esp_irq_at_pc_s, nullptr, 16)));
      }
    }
    if(dma_race_snoop_n != 0 or not watch_pa_s.empty()) {
      dma_race_config(dma_race_snoop_n, dma_race_copy_n, dma_race_apply);
      s->sun4m->dma_hook = dma_race_write;
      s->sun4m->dma_hook_ctx = s;
      s->sun4m->dma_snoop = dma_race_snoop;
      s->sun4m->dma_snoop_ctx = s;
    }
  }
  /* --console-input files, typed in turn: the next opens when one is used up */
  if(console_input_ats.size() > console_inputs.size()) {
    fprintf(stderr, "ss10sim: more --console-input-at than --console-input\n");
    return 1;
  }
  console_input_ats.resize(console_inputs.size(), 0);
  std::vector<int> con_fds;
  for(const std::string &f : console_inputs) {
    const int fd = (f == "-") ? 0 : open(f.c_str(), O_RDONLY);
    if(fd < 0) {
      fprintf(stderr, "ss10sim: cannot open --console-input %s\n", f.c_str());
      return 1;
    }
    con_fds.push_back(fd);
  }
  size_t con_idx = 0;
  int con_fd = con_fds.empty() ? -1 : con_fds[0];
  uint64_t console_input_at = con_fds.empty() ? 0 : console_input_ats[0];
  /* --kbd-input: the file as Sun key events (keycode | 0x80 = release) */
  std::vector<uint8_t> kbd_keys;
  if(not kbd_input.empty()) {
    FILE *kf = fopen(kbd_input.c_str(), "rb");
    if(kf == nullptr or s->sun4m == nullptr or not s->sun4m->have_kbd) {
      fprintf(stderr, "ss10sim: --kbd-input needs --tcx or --cg14 and a readable %s\n", kbd_input.c_str());
      return 1;
    }
    const uint8_t sun_shift = usb_to_sun(0xe1), sun_ctrl = usb_to_sun(0xe0);
    for(int c = fgetc(kf); c != EOF; c = fgetc(kf)) {
      bool shift = false;
      /* control characters (other than tab and newline): Control + the letter */
      if(c >= 1 and c <= 26 and c != '\t' and c != '\n') {
	const uint8_t k = usb_to_sun(0x04 + (c - 1));
	kbd_keys.push_back(sun_ctrl);
	kbd_keys.push_back(k);
	kbd_keys.push_back(k | 0x80);
	kbd_keys.push_back(sun_ctrl | 0x80);
	continue;
      }
      const uint8_t k = usb_to_sun(ascii_to_usb(static_cast<char>(c), &shift));
      if(k == 0) {
	continue;
      }
      if(shift) {
	kbd_keys.push_back(sun_shift);
      }
      kbd_keys.push_back(k);
      kbd_keys.push_back(k | 0x80);
      if(shift) {
	kbd_keys.push_back(sun_shift | 0x80);
      }
    }
    fclose(kf);
  }
  size_t kbd_pos = 0;
  uint64_t kbd_next = kbd_input_at;
  if(console_icount and s->sun4m) {
    s->sun4m->serial.line_icnt = &s->icnt;
    s->sun4m->serial.line_state = s;
  }
  fb_display *disp = nullptr;
  if(s->sun4m and (s->sun4m->tcx or s->sun4m->cg14) and (sdl or not fb_png.empty())) {
    framebuffer_t *fb = s->sun4m->cg14 ? static_cast<framebuffer_t *>(s->sun4m->cg14) : s->sun4m->tcx;
    disp = new fb_display(fb, sdl, fb_png, fb_png_every);
  }
  uint64_t next_pump = 0;
  const bool have_ckpt_pc = not ckpt_pc_s.empty();
  const uint32_t ckpt_pc = have_ckpt_pc ? static_cast<uint32_t>(std::stoul(ckpt_pc_s, nullptr, 0)) : 0;
  FILE *pcfp = pctrace.empty() ? nullptr : fopen(pctrace.c_str(), "w");
  if(trace) {
    trace_from = 0;
  }
  if(trace_from != ~0ULL) {
    initCapstone();
  }

  uint64_t halt_warps = 0;
  bool timer_fired = false;
  bool prev_exited = true;
  bool ckpt_armed = false;
  uint64_t n_exec = 0;       /* instructions executed here (icnt also counts halted time) */
  /* lean loop (indysim's): between events, iterations of the loop below whose
   * every per-boundary check is a no-op just run execSparc.  It stops at the
   * first boundary where one could act -- the next timer event, a console poll
   * point (icnt % 4096 == 0), a kbd or display pump time, the checkpoint
   * icnt/exec count, max_icnt -- or when the CPU halts, asks for a reset or
   * breaks, and that boundary runs the full loop body.  execSparc advances icnt
   * by at most 1, so no boundary is skipped.  Off with the per-instruction
   * debug outputs (--pctrace, --trace/--trace-from, --checkpoint-at-pc). */
  const bool lean_ok = (pcfp == nullptr) and (trace_from == ~0ULL) and not have_ckpt_pc;
  sun4m_t *const m4 = s->sun4m;
  while(not s->brk and s->icnt < max_icnt) {
    if(lean_ok and not ckpt_armed) {
      uint64_t lim = std::min(max_icnt, ckpt_icnt);
      if(kbd_pos < kbd_keys.size()) {
	lim = std::min(lim, kbd_next);
      }
      if(disp) {
	lim = std::min(lim, next_pump);
      }
      if(con_fd >= 0) {
	lim = std::min<uint64_t>(lim, (s->icnt & 4095) ? (s->icnt & ~4095ULL) + 4096 : s->icnt);
      }
      if(m4 and m4->cpu_halted) {
	lim = s->icnt;
      }
      n_exec += execSparcRun(s, lim, (ckpt_exec > n_exec) ? ckpt_exec - n_exec : 0);
      if(m4 and m4->reset_req) {
	system_reset(s);
      }
      if(s->brk or s->icnt >= max_icnt) {
	break;
      }
    }
    if(kbd_pos < kbd_keys.size() and s->icnt >= kbd_next and s->sun4m->kbd_ms.kbd_idle()) {
      const uint8_t k = kbd_keys[kbd_pos++];
      s->sun4m->kbd_ms.kbd_event(k & 0x7f, not (k & 0x80));
      s->sun4m->update_irqs(s);
      kbd_next = s->icnt + 200000;
    }
    if(disp and s->icnt >= next_pump) {
      disp->pump(s);
      next_pump = s->icnt + 65536;
    }
    /* typed console input: a byte when ttya's receiver is empty (checked every
     * 4K instructions; poll() so an interactive stdin never blocks the run) */
    if(con_fd >= 0 and s->sun4m and (s->icnt & 4095) == 0 and s->icnt >= console_input_at and
       s->sun4m->serial.can_receive(1)) {
      struct pollfd pfd = {con_fd, POLLIN, 0};
      uint8_t ch;
      if(poll(&pfd, 1, 0) > 0) {
	if(read(con_fd, &ch, 1) == 1) {
	  s->sun4m->serial.receive(1, (ch == '\n') ? '\r' : ch);
	  s->sun4m->update_irqs(s);
	}
	else {
	  if(con_fd != 0) {
	    close(con_fd);
	  }
	  con_fd = -1;
	  if(++con_idx < con_fds.size()) {
	    con_fd = con_fds[con_idx];
	    console_input_at = console_input_ats[con_idx];
	  }
	}
      }
    }
    if(s->sun4m and s->icnt >= s->sun4m->next_event_icnt) {
      s->sun4m->timer_event(s);
      timer_fired = true;
    }
    if(s->sun4m and s->sun4m->cpu_halted) {
      /* qemu sparc_cpu_has_work: wake when any interrupt level is requested and
       * traps are enabled, whatever the PIL (Linux idles with PIL 15 and takes
       * the interrupt after it lowers it) */
      if(s->et and s->irl != 0) {
	s->sun4m->cpu_halted = false;
	halt_warps = 0;
      }
      else {
	timer_fired = true;
	if(not s->sun4m->warp_to_next_event(s) or ++halt_warps > 1000000) {
	  intctl_t &ic = s->sun4m->intctl;
	  fprintf(stderr, "ss10sim: CPU halted for good at pc 0x%x: et %d pil %u irl %u, intctl master pending %08x "
		  "disabled %08x, cpu0 pending %08x, timer limits sys %llx cpu0 %llx, mode %x\n",
		  s->pc, s->et, s->pil, s->irl, ic.master_pending, ic.master_disabled, ic.slave_pending[0],
		  static_cast<unsigned long long>(s->sun4m->ctr[0].limit),
		  static_cast<unsigned long long>(s->sun4m->ctr[1].limit), s->sun4m->ctr_user_mode);
	  break;
	}
	continue;
      }
    }
    /* trace the instructions that execute: a pending interrupt is taken before
     * the instruction at pc is fetched.  Matching qemu's -icount exec log, the
     * pc is also traced when a timer event fired at this boundary and the last
     * TB chained into the next one: qemu has then already started (and logged)
     * the next one-insn TB when the deadline stops it, and re-executes it after
     * the interrupt is handled.  A TB that returned to qemu's main loop (see
     * qemu_tb_exits, a trap, a halt) is followed by no such entry. */
    if((timer_fired and not prev_exited) or not (s->et and s->irl != 0 and (s->irl == 15 or s->irl > s->pil))) {
      if(pcfp) {
        fprintf(pcfp, "%08x\n", s->pc);
      }
      if(s->icnt >= trace_from) {
        uint32_t inst = 0;
        debug_fetch(s, s->pc, &inst);
        fprintf(stderr, "%08x %08x cwp %u pil %u irl %u et %d icnt %llu : %s\n", s->pc, inst, s->cwp, s->pil, s->irl,
		s->et, static_cast<unsigned long long>(s->icnt), getAsmString(inst, s->pc).c_str());
      }
    }
    /* the first boundary at/after the requested one with npc == pc + 4 (the
     * RTL resumes a checkpoint from a single pc) */
    if(s->icnt >= ckpt_icnt or n_exec >= ckpt_exec or (have_ckpt_pc and s->pc == ckpt_pc)) {
      ckpt_armed = true;
    }
    if(ckpt_armed and s->npc == s->pc + 4 and not (s->sun4m and s->sun4m->cpu_halted)) {
      save_checkpoint(ckpt_out.c_str(), s);
      break;
    }
    timer_fired = false;
    uint64_t ntraps0 = s->ntraps;
    uint32_t insn = 0;
    if(pcfp) {
      debug_fetch(s, s->pc, &insn);
    }
    execSparc(s);
    n_exec++;
    prev_exited = (s->ntraps != ntraps0) or qemu_tb_exits(insn) or (s->sun4m and s->sun4m->cpu_halted);
    if(s->sun4m and s->sun4m->reset_req) {
      system_reset(s);
    }
  }

  delete disp;               /* (the final --fb-png) */
  if(dump) {
    std::cerr << *s;
  }
  dma_race_report();
  std::cerr << "ISS: executed " << n_exec << " instructions\n";
  std::cerr << "ISS: " << s->icnt << " insns, exit code " << s->exit_code
	    << (s->error_mode ? " (error mode)" : "") << "\n";
  if(trace_from != ~0ULL) {
    stopCapstone();
  }
  if(pcfp) {
    fclose(pcfp);
  }
  int rc = s->exit_code;
  delete s;
  return rc;
}
