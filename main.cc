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
			uint32_t first_id) {
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
    m->scsi[id] = d;
    fprintf(stderr, "scsi: target %u: %s\n", id, path.c_str());
  }
  return true;
}

/* qemu sun4m_hw_init's fw_cfg items and -kernel load: the kernel's segments go
 * to RAM at vaddr - 0xf0000000 (KERNEL_LOAD_ADDR 0x4000 is where its text
 * lands), the command line to 0x7ff000.  The values match qemu -M SS-20 with
 * one CPU and -nographic. */
static bool setup_fw_cfg(state_t *s, const std::string &kernel, const std::string &append) {
  static const uint32_t KERNEL_LOAD_ADDR = 0x4000, CMDLINE_ADDR = 0x7ff000, INITRD_LOAD_ADDR = 0x800000;
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
  s->s = true;
  s->ps = true;
  s->et = false;
  s->pil = 0;
  s->cwp = 0;
  s->wim = 1;
  s->tbr = 0;
  s->y = 0;
  s->fsr = 0;
  s->fq_addr = s->fq_insn = 0;
  s->mmu_ctrl = (s->mmu_ctrl & ~(MCR_E | MCR_NF)) | MCR_BMODE;
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
  uint64_t ckpt_icnt = ~0ULL;
  std::string ckpt_pc_s, ckpt_out = "ss10sim.ckpt", restore;
  std::string kernel, append;
  std::vector<std::string> scsi_disks, scsi_cdroms;
  std::string console_input;
  uint64_t console_input_at = 0;
  uint64_t max_icnt = ~0ULL;
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
      ("scsi-disk", po::value<std::vector<std::string>>(&scsi_disks)->composing(),
       "[ID:]image: a SCSI disk on the ESP (default ID 0, then 1, ...; written in place)")
      ("scsi-cdrom", po::value<std::vector<std::string>>(&scsi_cdroms)->composing(),
       "[ID:]image: a SCSI CD-ROM on the ESP (default ID 6, as an SS-20's)")
      ("console-input", po::value<std::string>(&console_input),
       "file (or - for stdin) typed into ttya, one byte whenever its receiver is empty; \\n is sent as \\r")
      ("console-input-at", po::value<uint64_t>(&console_input_at),
       "with --console-input: start typing at this icount (so start-up code cannot swallow it)")
      ("checkpoint-at", po::value<uint64_t>(&ckpt_icnt), "write a checkpoint (--checkpoint-out) when icnt reaches this, then exit")
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
  initState(s);
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
    if(not attach_scsi(s->sun4m, scsi_disks, scsi_dev_t::type_t::disk, 0) or
       not attach_scsi(s->sun4m, scsi_cdroms, scsi_dev_t::type_t::cdrom, 6)) {
      return 1;
    }
    s->ram_size = static_cast<uint64_t>(ram_mb) << 20;
    if(not setup_fw_cfg(s, kernel, append)) {
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
  int con_fd = -1;
  if(not console_input.empty()) {
    con_fd = (console_input == "-") ? 0 : open(console_input.c_str(), O_RDONLY);
    if(con_fd < 0) {
      fprintf(stderr, "ss10sim: cannot open --console-input %s\n", console_input.c_str());
      return 1;
    }
  }
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
  while(not s->brk and s->icnt < max_icnt) {
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
    if(s->icnt >= ckpt_icnt or (have_ckpt_pc and s->pc == ckpt_pc)) {
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
    prev_exited = (s->ntraps != ntraps0) or qemu_tb_exits(insn) or (s->sun4m and s->sun4m->cpu_halted);
    if(s->sun4m and s->sun4m->reset_req) {
      system_reset(s);
    }
  }

  if(dump) {
    std::cerr << *s;
  }
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
