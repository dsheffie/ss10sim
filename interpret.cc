#include <set>
#include <tuple>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cfenv>
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>

#include "interpret.hh"
#include "sun4m.hh"
#include "helper.hh"
#include "disassemble.hh"
#include "globals.hh"

/* SPARC V8 golden ISS.  References: The SPARC Architecture Manual, Version 8
 * (chapters 4-7 and appendix B).  Mapping onto the r9999 pipeline and the open
 * design decisions live in SPARC_V8_PLAN.md.
 *
 * Memory model: SPARC Reference MMU (sun4m, Viking flavor) walked on every
 * access -- no TLB, so TLB flushes are no-ops.  No caches are modeled. */

#pragma STDC FENV_ACCESS ON

static const uint32_t NO_TRAP = ~0u;

state_t::~state_t() {}

uint32_t state_t::get_psr() const {
  /* EC (bit 13) is hardwired 0: no coprocessor */
  return (PSR_IMPL_VER << 24) |
    (static_cast<uint32_t>(icc_n) << 23) |
    (static_cast<uint32_t>(icc_z) << 22) |
    (static_cast<uint32_t>(icc_v) << 21) |
    (static_cast<uint32_t>(icc_c) << 20) |
    (static_cast<uint32_t>(ef) << 12) |
    (pil << 8) |
    (static_cast<uint32_t>(s) << 7) |
    (static_cast<uint32_t>(ps) << 6) |
    (static_cast<uint32_t>(et) << 5) |
    cwp;
}

void state_t::set_psr(uint32_t v) {
  icc_n = (v >> 23) & 1;
  icc_z = (v >> 22) & 1;
  icc_v = (v >> 21) & 1;
  icc_c = (v >> 20) & 1;
  ef = ((v >> 12) & 1) and not no_fpu;
  pil = (v >> 8) & 15;
  set_s((v >> 7) & 1);
  ps = (v >> 6) & 1;
  et = (v >> 5) & 1;
  cwp = v & 31;
}

void initState(state_t *s) {
  /* V8 reset: PC=0, nPC=4, S=1, ET=0.  load_elf overrides pc/npc. */
  s->s = true;
  s->et = false;
  s->ef = true;
  s->cwp = 0;
  s->wim = 0;
  if(s->user_emu) {
    /* a fresh Linux process: user mode, traps on, one valid window (CWP); the
     * window above it is the invalid one, so the first RESTORE past _start
     * underflows and N-1 SAVEs fit before the first spill */
    s->set_s(false);
    s->ps = false;
    s->et = true;
    s->wim = 1u << ((s->cwp + 1) % NWINDOWS);
  }
}

std::ostream &operator<<(std::ostream &out, const state_t &s) {
  static const char *names[32] = {
    "g0","g1","g2","g3","g4","g5","g6","g7",
    "o0","o1","o2","o3","o4","o5","sp","o7",
    "l0","l1","l2","l3","l4","l5","l6","l7",
    "i0","i1","i2","i3","i4","i5","fp","i7"
  };
  out << std::hex << "pc " << s.pc << " npc " << s.npc
      << " psr " << s.get_psr() << " wim " << s.wim
      << " tbr " << s.tbr << " y " << s.y << "\n";
  for(int i = 0; i < 32; i++) {
    out << names[i] << " " << std::setw(8) << std::setfill('0')
	<< s.r[widx(s.cwp, i)] << ((i & 7) == 7 ? "\n" : " ");
  }
  out << std::dec << std::setfill(' ');
  return out;
}

/* ---------------------------------------------------------------- memory */

static inline uint8_t  be(uint8_t x)  { return x; }
static inline uint16_t be(uint16_t x) { return __builtin_bswap16(x); }
static inline uint32_t be(uint32_t x) { return __builtin_bswap32(x); }

/* the board DMA race model (--dma-race, below the decoded-instruction cache):
 * nonzero while a DMA-written line is still inside its board window */
static uint32_t g_dw_active = 0;
static void dma_race_access_slow(state_t *s, uint64_t pa, bool is_store);
static void dma_race_close(state_t *s);
/* --watch-pa: every CPU access to [g_watch_lo, g_watch_hi) is logged (pc, icnt, the
 * aligned word before the access); g_watch_on folds into the same cheap gate */
static uint32_t g_watch_on = 0;
static uint64_t g_watch_lo = 0, g_watch_hi = 0;
static void watch_access(state_t *s, uint64_t pa, bool is_store);
static inline void dma_race_access(state_t *s, uint64_t pa, bool is_store) {
  if(__builtin_expect((g_dw_active | g_watch_on) != 0, 0)) {
    if(g_watch_on and pa >= g_watch_lo and pa < g_watch_hi) {
      watch_access(s, pa, is_store);
    }
    if(g_dw_active != 0) {
      dma_race_access_slow(s, pa, is_store);
    }
  }
}

/* Physical space is 36 bits.  RAM is sparse_mem below ram_size (sun4m RAM sits
 * at PA 0); everything else, including PA >= 4GB, is sun4m device space. */
template <typename T>
static T ld_phys(state_t *s, uint64_t pa) {
  if(pa < s->ram_size) {
    dma_race_access(s, pa, false);
    return be(s->mem.get<T>(pa));
  }
  if(s->dev) {
    return static_cast<T>(s->dev->read(s, pa, sizeof(T), &s->bus_error));
  }
  if(s->sun4m) {
    /* on the board the ARM answers a device load only after its DMA call returns */
    if(__builtin_expect(g_dw_active != 0, 0)) {
      dma_race_close(s);
    }
    return static_cast<T>(s->sun4m->read(s, pa, sizeof(T), &s->bus_error));
  }
  fprintf(stderr, "ISS: load from unmodeled pa 0x%llx pc 0x%x\n", static_cast<unsigned long long>(pa), s->pc);
  return 0;
}

/* a store into a RAM page that holds decoded instructions empties its slots
 * (the decoded-instruction cache, with execute below) */
static inline void code_write_check(uint64_t pa);

template <typename T>
static void st_phys(state_t *s, uint64_t pa, T v) {
  if(pa < s->ram_size) {
    code_write_check(pa);
    dma_race_access(s, pa, true);
    s->mem.set<T>(pa, be(v));
    return;
  }
  if(s->dev) {
    s->dev->write(s, pa, sizeof(T), v, &s->bus_error);
    return;
  }
  if(s->sun4m) {
    s->sun4m->write(s, pa, sizeof(T), v, &s->bus_error);
    return;
  }
  fprintf(stderr, "ISS: store to unmodeled pa 0x%llx pc 0x%x\n", static_cast<unsigned long long>(pa), s->pc);
}

/* ASIs that reach memory: 8/9 user/supervisor insn, 0xa/0xb user/supervisor
 * data (translated), 0x20-0x2f MMU bypass with PA[35:32] = ASI[3:0] */
static inline bool asi_is_bypass(uint32_t asi) {
  return (asi & 0xf0) == 0x20;
}

static inline bool asi_is_memory(uint32_t asi) {
  return asi == 0x8 or asi == 0x9 or asi == 0xa or asi == 0xb or asi_is_bypass(asi);
}

enum class acc_t { load, store, fetch };

/* SRMMU table walk (on a soft-TLB miss; see mmu_xlate).  Returns FT_NONE with
 * the PTE, the PA it was read from and its level (0 = context, 4GB; 1 = 16MB;
 * 2 = 256KB; 3 = 4KB), else the fault type with *level where it hit. */
static uint32_t srmmu_walk(state_t *s, uint32_t va, uint32_t *pte, uint64_t *pte_pa, uint32_t *level) {
  uint64_t ea = (static_cast<uint64_t>(s->mmu_ctpr & ~3u) << 4) + 4*static_cast<uint64_t>(s->mmu_ctx);
  for(uint32_t l = 0; ; l++) {
    uint32_t e = ld_phys<uint32_t>(s, ea);
    *level = l;
    switch(e & 3)
      {
      case 2:                 /* PTE */
	*pte = e;
	*pte_pa = ea;
	return FT_NONE;
      case 0:                 /* invalid */
	return FT_INVALID;
      case 3:                 /* reserved */
	return FT_TRANSLATION;
      default:
	break;
      }
    if(l == 3) {              /* a PTD at level 3 */
      return FT_TRANSLATION;
    }
    uint32_t idx = (l == 0) ? ((va >> 24) & 0xff) : (l == 1) ? ((va >> 18) & 0x3f) : ((va >> 12) & 0x3f);
    ea = (static_cast<uint64_t>(e & ~3u) << 4) + 4*idx;
  }
}

/* SRMMU probe (lda ASI 3, V8 appendix H): va[11:8] is the probe type -- 0 page,
 * 1 segment, 2 region, 3 context, 4 entire.  The walk stops at the type's level
 * and returns the entry there (a PTD as well as a PTE); a PTE met earlier is
 * returned, an invalid or reserved entry gives 0.  Matches qemu's mmu_probe.
 * Solaris's vik_mmu_probe relies on it: a region probe that returned the
 * 4K leaf PTE looked like a 16MB region mapping and gave a bogus PA (the
 * "munged phys_avail list" panic). */
static uint32_t srmmu_probe(state_t *s, uint32_t va) {
  const uint32_t type = (va >> 8) & 0xf;
  if(type > 4) {
    return 0;
  }
  /* walk level of each type: page/entire = the leaf (3), segment 2, region 1, context 0 */
  static const uint32_t stop_level[5] = {3, 2, 1, 0, 3};
  uint64_t ea = (static_cast<uint64_t>(s->mmu_ctpr & ~3u) << 4) + 4*static_cast<uint64_t>(s->mmu_ctx);
  for(uint32_t l = 0; ; l++) {
    uint32_t e = ld_phys<uint32_t>(s, ea);
    if((e & 3) == 2) {
      return e;
    }
    if((e & 3) != 1) {
      return 0;
    }
    if(l == 3) {              /* a PTD at level 3 */
      return 0;
    }
    if(l == stop_level[type]) {
      return e;
    }
    uint32_t idx = (l == 0) ? ((va >> 24) & 0xff) : (l == 1) ? ((va >> 18) & 0x3f) : ((va >> 12) & 0x3f);
    ea = (static_cast<uint64_t>(e & ~3u) << 4) + 4*idx;
  }
}

static inline uint64_t pte_pa_of(uint32_t pte, uint32_t level, uint32_t va) {
  static const uint32_t off_mask[4] = {0xffffffffu, 0x00ffffffu, 0x0003ffffu, 0x00000fffu};
  uint64_t base = static_cast<uint64_t>(pte >> 8) << 12;
  return (base & ~static_cast<uint64_t>(off_mask[level])) | (va & off_mask[level]);
}

bool debug_walk(state_t *s, uint32_t va, uint32_t *pte, uint32_t *level, uint64_t *pa) {
  uint64_t pte_pa = 0;
  if(srmmu_walk(s, va, pte, &pte_pa, level) != FT_NONE) {
    return false;
  }
  *pa = pte_pa_of(*pte, *level, va);
  return true;
}

bool debug_fetch(state_t *s, uint32_t va, uint32_t *insn) {
  uint64_t pa = va;
  if(not (s->mmu_ctrl & MCR_E)) {
    if(s->mmu_ctrl & MCR_BMODE) {
      pa = SUN4M_PROM_BASE | (va & 0x7ffffu);
    }
  }
  else {
    uint32_t pte = 0, level = 0;
    uint64_t pte_pa = 0;
    if(srmmu_walk(s, va, &pte, &pte_pa, &level) != FT_NONE) {
      return false;
    }
    pa = pte_pa_of(pte, level, va);
  }
  /* RAM and the PROM have no read side effects */
  if(pa < s->ram_size) {
    *insn = be(s->mem.get<uint32_t>(pa));
    return true;
  }
  if(s->sun4m and pa >= SUN4M_PROM_BASE and pa + 4 <= SUN4M_PROM_BASE + SUN4M_PROM_SIZE) {
    const uint8_t *p = &s->sun4m->prom[pa - SUN4M_PROM_BASE];
    *insn = (static_cast<uint32_t>(p[0]) << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    return true;
  }
  return false;
}

/* translation/protection fault.  A fault status not yet read is replaced and
 * flagged OW (as qemu does). */
static void mmu_record_fault(state_t *s, uint32_t ft, uint32_t level, uint32_t at, uint32_t va) {
  uint32_t ow = (s->mmu_fsr != 0) ? MFSR_OW : 0;
  s->mmu_fsr = (level << MFSR_L_SHIFT) | (at << MFSR_AT_SHIFT) | (ft << MFSR_FT_SHIFT) | MFSR_FAV | ow;
  s->mmu_far = va;
}

/* access bus error (unassigned physical address), recorded as qemu's
 * sparc_raise_mmu_fault: it does not overwrite a pending translation fault,
 * sets bit 16 for an explicit-ASI access, and SuperSPARC never puts an
 * instruction fault address in the FAR.  Returns true if it traps (MMU on and
 * not no-fault). */
static bool mmu_bus_error(state_t *s, uint64_t pa, bool is_write, bool is_exec, bool is_asi) {
  uint32_t prev_ft = (s->mmu_fsr >> MFSR_FT_SHIFT) & 7;
  s->bus_error = false;
  if(prev_ft > 4 or prev_ft == 0) {
    s->mmu_fsr = (is_asi ? (1u << 16) : 0) | (s->s ? (1u << 5) : 0) | (is_exec ? (1u << 6) : 0) |
      (is_write ? (1u << 7) : 0) | (FT_BUS_ERROR << MFSR_FT_SHIFT) | MFSR_FAV;
    if(not is_exec) {
      s->mmu_far = static_cast<uint32_t>(pa);
    }
  }
  if(prev_ft == ((s->mmu_fsr >> MFSR_FT_SHIFT) & 7)) {
    s->mmu_fsr |= MFSR_OW;
  }
  return (s->mmu_ctrl & MCR_E) and not (s->mmu_ctrl & MCR_NF);
}

/* Translate va for an access through a memory ASI.  Returns FT_NONE and *pa, or
 * the fault type (already recorded in the fault status/address registers).
 * *pte_out gets the PTE (R/M already updated) of a successful table walk, or 0
 * when the translation did not come from the page tables (bypass, MMU off). */
static __attribute__((noinline)) uint32_t mmu_xlate_slow(state_t *s, uint32_t asi, uint32_t va, acc_t acc,
							 uint64_t *pa, uint32_t *pte_out) {
  *pte_out = 0;
  if(asi_is_bypass(asi)) {
    *pa = (static_cast<uint64_t>(asi & 0xf) << 32) | va;
    return FT_NONE;
  }
  if(not (s->mmu_ctrl & MCR_E)) {
    /* Viking boot mode: MMU-off instruction-space accesses come from the PROM
     * (offset masked to 512KB, as qemu does): fetches, and loads through the
     * instruction ASIs 8/9 (OBP's POST reads its tables with lduba ASI 9; qemu
     * treats those ASIs as code accesses).  Data ASIs go to RAM. */
    if(acc != acc_t::store and (acc == acc_t::fetch or asi == 0x8 or asi == 0x9) and (s->mmu_ctrl & MCR_BMODE)) {
      *pa = SUN4M_PROM_BASE | (va & 0x7ffffu);
    }
    else {
      *pa = va;
    }
    return FT_NONE;
  }
  /* ACC permissions: bit 0 = read, 1 = write, 2 = execute */
  static const uint8_t perm_user[8] = {1, 3, 5, 7, 4, 1, 0, 0};
  static const uint8_t perm_super[8] = {1, 3, 5, 7, 4, 3, 5, 7};
  const bool super = (asi == 0x9 or asi == 0xb);
  const uint32_t at = ((acc == acc_t::store) ? 4 : 0) | ((acc == acc_t::fetch) ? 2 : 0) | (super ? 1 : 0);
  uint32_t pte = 0, level = 0;
  uint64_t pte_pa = 0;
  uint32_t ft = srmmu_walk(s, va, &pte, &pte_pa, &level);
  if(ft == FT_NONE) {
    uint32_t a = (pte >> 2) & 7;
    uint32_t need = (acc == acc_t::load) ? 1 : (acc == acc_t::store) ? 2 : 4;
    if(not ((super ? perm_super[a] : perm_user[a]) & need)) {
      ft = (not super and a >= 6) ? FT_PRIVILEGE : FT_PROTECTION;
    }
  }
  if(ft != FT_NONE) {
    mmu_record_fault(s, ft, level, at, va);
    return ft;
  }
  /* referenced on every access, modified on a store */
  uint32_t npte = pte | (1u << 5) | ((acc == acc_t::store) ? (1u << 6) : 0);
  if(npte != pte) {
    st_phys<uint32_t>(s, pte_pa, npte);
  }
  *pa = pte_pa_of(pte, level, va);
  *pte_out = npte;
  return FT_NONE;
}

/* ---- software TLB (indysim's soft TLB, Bedichek's figure 5) ----------------
 * A direct-mapped cache of successful table walks, keyed by 4K virtual page +
 * context, one table for data and one for instruction fetch.  perm has bit
 * (super ? 3 : 0) + acc for each access the PTE allows; the store bits are set
 * only once the PTE's M bit is set, so the first store to a page still walks
 * and sets M (R is set by the walk that fills the entry).  Like a real SRMMU
 * TLB it does not snoop page-table writes: the OS flushes (ASI 3) after
 * changing a PTE, and that empties it, as do context-table-pointer and
 * control-register writes.  A context switch just misses (the context is in
 * the tag). */
struct stlb_t {
  uint64_t tag;                        /* ((ctx << 20) | vpage) + 1; 0 = empty */
  uint64_t ppage;                      /* PA of the 4K page */
  uint32_t perm;
};
static const uint32_t STLB_SZ = 256;
static stlb_t g_stlb[2][STLB_SZ];      /* [0] loads + stores, [1] instruction fetch */

/* fetch-page cache (indysim's): the host bytes of the page the last fetch
 * came from, when that is RAM or the PROM (no read side effects), keyed by
 * page + context + supervisor bit.  Emptied with the soft TLB, which also
 * covers MMU-off boot-mode fetches (an MCR write flushes). */
static uint64_t g_fc_tag = 0;          /* ((s << 36) | (ctx << 20) | vpage) + 1; 0 = empty */
static const uint8_t *g_fc_host = nullptr;

void mmu_tlb_flush() {
  memset(g_stlb, 0, sizeof(g_stlb));
  g_fc_tag = 0;
}

static inline uint32_t stlb_perm(uint32_t pte) {
  static const uint8_t perm_user[8] = {1, 3, 5, 7, 4, 1, 0, 0};
  static const uint8_t perm_super[8] = {1, 3, 5, 7, 4, 3, 5, 7};
  const uint32_t a = (pte >> 2) & 7;
  /* rwx (bits 0-2) -> load/store/fetch (acc_t order: load 0, store 1, fetch 2) */
  uint32_t u = perm_user[a], k = perm_super[a];
  if(not (pte & (1u << 6))) {          /* not yet modified: a store must walk */
    u &= ~2u;
    k &= ~2u;
  }
  return u | (k << 3);
}

/* a soft-TLB hit for this access, with no side effects (a miss walks in
 * mmu_xlate_slow) */
static inline bool stlb_hit(const state_t *s, uint32_t asi, uint32_t va, acc_t acc, uint64_t *pa) {
  const bool super = (asi == 0x9 or asi == 0xb);
  const uint32_t need = 1u << ((super ? 3 : 0) + static_cast<uint32_t>(acc));
  const uint64_t tag = ((static_cast<uint64_t>(s->mmu_ctx) << 20) | (va >> 12)) + 1;
  const stlb_t &e = g_stlb[acc == acc_t::fetch][(va >> 12) & (STLB_SZ - 1)];
  if(e.tag == tag and (e.perm & need) and (s->mmu_ctrl & MCR_E) and not asi_is_bypass(asi)) {
    *pa = e.ppage | (va & 0xfffu);
    return true;
  }
  return false;
}

/* --vram-map-log: each distinct translation that lands on the CG14 (VRAM at
 * 0xfc000000 + 64 MB, registers at 0x9c000000) is printed once, with its PTE's C
 * bit: how each OS maps the framebuffer (cacheable or not) -- Kodiak puts the VRAM
 * in DRAM behind the core's caches.  Hooked at the soft-TLB refill, so a TLB hit
 * costs nothing; a bypass ASI (never cached) walks every time and is deduped. */
static bool g_vram_log = false;
static std::set<std::tuple<uint32_t, uint64_t, uint32_t, uint32_t, uint32_t>> g_vram_seen;
void vram_map_log_config(bool on) {
  g_vram_log = on;
}
static __attribute__((noinline)) void vram_map_note(state_t *s, uint32_t asi, uint32_t va, acc_t acc,
						     uint64_t pa, uint32_t pte) {
  const bool vram = (pa >= 0xfc000000ULL and pa < 0x100000000ULL);
  const bool regs = (pa >= 0x9c000000ULL and pa < 0x9c007000ULL);
  if(not vram and not regs) {
    return;
  }
  const bool mmu_on = (s->mmu_ctrl & MCR_E) != 0;
  const bool bypass = asi_is_bypass(asi) or not mmu_on;
  /* the cacheability the access gets: the PTE's C with the MMU on, never a bypass */
  const uint32_t c = bypass ? 0 : ((pte >> 7) & 1);
  if(not g_vram_seen.insert(std::make_tuple(va >> 12, pa >> 12, bypass ? 0 : pte, asi,
					    static_cast<uint32_t>(acc))).second) {
    return;
  }
  fprintf(stderr, "vram-map: icnt %llu pc %08x %s va %08x pa %09llx pte %08x C=%u asi %02x %s%s\n",
	  static_cast<unsigned long long>(s->icnt), s->pc, vram ? "vram" : "regs", va,
	  static_cast<unsigned long long>(pa), bypass ? 0 : pte, c, asi,
	  (acc == acc_t::store) ? "st" : (acc == acc_t::fetch) ? "fetch" : "ld",
	  bypass ? " (bypass/MMU off)" : "");
}

static inline uint32_t mmu_xlate(state_t *s, uint32_t asi, uint32_t va, acc_t acc, uint64_t *pa) {
  if(__builtin_expect(stlb_hit(s, asi, va, acc, pa), 1)) {
    return FT_NONE;
  }
  const uint64_t tag = ((static_cast<uint64_t>(s->mmu_ctx) << 20) | (va >> 12)) + 1;
  stlb_t &e = g_stlb[acc == acc_t::fetch][(va >> 12) & (STLB_SZ - 1)];
  uint32_t pte = 0;
  const uint32_t ft = mmu_xlate_slow(s, asi, va, acc, pa, &pte);
  if(__builtin_expect(g_vram_log, false) and ft == FT_NONE) {
    vram_map_note(s, asi, va, acc, *pa, pte);
  }
  if(ft == FT_NONE and pte != 0) {
    e.tag = tag;
    e.ppage = *pa & ~0xfffULL;
    e.perm = stlb_perm(pte);
  }
  return ft;
}

/* Viking cache/tag/flush ASIs: no caches are modeled, so loads read 0 (every tag
 * invalid, which ends Linux's tag-walking flush loops) and stores are dropped.
 * 0xc-0xf are the SuperSPARC I/D-cache tag and data diagnostics (OpenBIOS
 * clears the tags at startup). */
static inline bool asi_is_viking_cache(uint32_t asi) {
  return (asi >= 0xc and asi <= 0xf) or (asi >= 0x10 and asi <= 0x14) or asi == 0x18 or
    (asi >= 0x36 and asi <= 0x3f);
}

/* the ASI 0x2 module register a word address selects (the high word of the
 * 64-bit register at +0, the low word at +4), or -1 */
static int mxcc_reg(uint32_t va) {
  switch(va & ~7u)
    {
    case 0x01c00a00: return 3;
    case 0x01c00c00: return 5;
    case 0x01c00e00: return 6;
    case 0x01c00f00: return 7;
    default: return -1;
    }
}

/* non-memory ASIs (lda/sta): module registers (0x2), SRMMU probe/flush (0x3)
 * and registers (0x4) */
static uint32_t asi_load(state_t *s, uint32_t asi, uint32_t va) {
  if(asi == 0x2 and va >= 0x01c00000 and va < 0x01c00020) {
    uint64_t d = s->mxccdata[(va >> 3) & 3];
    return (va & 4) ? static_cast<uint32_t>(d) : static_cast<uint32_t>(d >> 32);
  }
  if(asi == 0x2 and mxcc_reg(va) >= 0) {
    uint64_t r = s->mxcc[mxcc_reg(va)];
    return (va & 4) ? static_cast<uint32_t>(r) : static_cast<uint32_t>(r >> 32);
  }
  if(asi == 0x3) {
    return srmmu_probe(s, va);
  }
  if(asi == 0x4c) {
    return s->mmu_bpaction;
  }
  if(asi == 0x4) {
    switch(va & 0xf00)
      {
      case 0x000: return s->mmu_ctrl;
      case 0x100: return s->mmu_ctpr;
      case 0x200: return s->mmu_ctx;
      case 0x300: {           /* reading the fault status clears it */
	uint32_t v = s->mmu_fsr;
	s->mmu_fsr = 0;
	return v;
      }
      case 0x400: return s->mmu_far;
      default: break;
      }
  }
  if(not asi_is_viking_cache(asi)) {
    fprintf(stderr, "ISS: load from unmodeled asi 0x%x va 0x%x pc 0x%x\n", asi, va, s->pc);
  }
  return 0;
}

static void asi_store(state_t *s, uint32_t asi, uint32_t va, uint32_t v) {
  if(asi == 0x2 and va >= 0x01c00000 and va < 0x01c00020) {
    uint64_t &d = s->mxccdata[(va >> 3) & 3];
    d = (va & 4) ? ((d & 0xffffffff00000000ULL) | v) : ((d & 0xffffffffULL) | (static_cast<uint64_t>(v) << 32));
    return;
  }
  if(asi == 0x2 and (va & ~4u) == 0x01c00100) {
    /* stream source: the register is 64 bits (the high word first); the copy
     * runs when the low word, which holds the physical address, lands */
    if(va & 4) {
      for(uint32_t i = 0; i < 4; i++) {
	uint64_t pa = v + 8 * i;
	s->mxccdata[i] = (static_cast<uint64_t>(ld_phys<uint32_t>(s, pa)) << 32) | ld_phys<uint32_t>(s, pa + 4);
      }
    }
    return;
  }
  if(asi == 0x2 and (va & ~4u) == 0x01c00200) {
    if(va & 4) {
      for(uint32_t i = 0; i < 4; i++) {
	uint64_t pa = v + 8 * i;
	st_phys<uint32_t>(s, pa, static_cast<uint32_t>(s->mxccdata[i] >> 32));
	st_phys<uint32_t>(s, pa + 4, static_cast<uint32_t>(s->mxccdata[i]));
      }
    }
    return;
  }
  if(asi == 0x2 and mxcc_reg(va) >= 0) {
    int r = mxcc_reg(va);
    uint64_t m = (va & 4) ? 0xffffffffULL : 0xffffffff00000000ULL;
    uint64_t w = (va & 4) ? v : (static_cast<uint64_t>(v) << 32);
    if(r == 6) {             /* error register: writing 1 clears the bit */
      s->mxcc[6] &= ~(w & m);
    }
    else {
      s->mxcc[r] = (s->mxcc[r] & ~m) | w;
    }
    return;
  }
  if(asi == 0x3) {          /* TLB flush: empty the whole soft TLB, whatever the flush type */
    mmu_tlb_flush();
    return;
  }
  if(asi == 0x4c) {
    s->mmu_bpaction = v & 0x1fffu;
    return;
  }
  if(asi == 0x4) {
    switch(va & 0xf00)
      {
      case 0x000: s->mmu_ctrl = v & 0x00ffffffu; mmu_tlb_flush(); return;   /* impl/ver read 0 */
      case 0x100: s->mmu_ctpr = v & ~3u; mmu_tlb_flush(); return;
      case 0x200: s->mmu_ctx = v & 0xffff; return;
      case 0x300: case 0x400: return;
      default: break;
      }
  }
  if(not asi_is_viking_cache(asi)) {
    fprintf(stderr, "ISS: store to unmodeled asi 0x%x va 0x%x pc 0x%x\n", asi, va, s->pc);
  }
}

/* user-emulation helpers (emu_spill/fill/syscall): MMU off there, so no faults */
template <typename T>
static T ld_mem(state_t *s, uint32_t asi, uint32_t va) {
  uint64_t pa = 0;
  uint32_t ft = mmu_xlate(s, asi, va, acc_t::load, &pa);
  assert(ft == FT_NONE);
  return ld_phys<T>(s, pa);
}

template <typename T>
static void st_mem(state_t *s, uint32_t asi, uint32_t va, T v) {
  uint64_t pa = 0;
  uint32_t ft = mmu_xlate(s, asi, va, acc_t::store, &pa);
  assert(ft == FT_NONE);
  st_phys<T>(s, pa, v);
}

/* ---------------------------------------------------------------- traps */

static void take_trap(state_t *s, uint32_t tt) {
  s->last_tt = tt;
  s->ntraps++;
  if(s->user_emu) {
    fprintf(stderr, "ISS: unhandled trap tt 0x%x at pc 0x%x (user emulation)\n", tt, s->pc);
    s->brk = true;
    s->exit_code = -1;
    return;
  }
  if(not s->et) {
    /* a trap with ET=0 enters error mode (on sun4m the watchdog then resets) */
    fprintf(stderr, "ISS: error mode, tt 0x%x at pc 0x%x\n", tt, s->pc);
    s->error_mode = true;
    s->brk = true;
    return;
  }
  s->et = false;
  s->ps = s->s;
  s->set_s(true);
  s->cwp = (s->cwp + NWINDOWS - 1) % NWINDOWS;
  s->gpr(17) = s->pc;    /* %l1 */
  s->gpr(18) = s->npc;   /* %l2 */
  s->tbr = (s->tbr & 0xfffff000u) | ((tt & 0xff) << 4);
  s->pc = s->tbr;
  s->npc = s->tbr + 4;
}

/* --user: the Linux kernel's window spill/fill, done inline instead of trapping.
 *
 * SAVE at CWP=C found WIM[C-1] set.  The valid windows are C..C-2 (newest to
 * oldest); the invalid window C-1's outs hold the oldest window's ins.  Spill the
 * oldest window (C-2): its locals+ins go to its own %sp (= its %o6).  C-2 becomes
 * the invalid window. */
static void emu_spill(state_t *s) {
  uint32_t w = (s->cwp + NWINDOWS - 2) % NWINDOWS;
  uint32_t sp = s->r[widx(w, 14)];
  for(uint32_t i = 0; i < 16; i++) {
    st_mem<uint32_t>(s, 0xa, sp + 4*i, s->r[widx(w, 16 + i)]);
  }
  s->wim = 1u << w;
}

/* RESTORE at CWP=C found WIM[C+1] set: reload the caller window C+1's locals+ins
 * from its %sp (= our %fp; its outs alias our ins and are live), then C+2 is the
 * invalid window. */
static void emu_fill(state_t *s) {
  uint32_t w = (s->cwp + 1) % NWINDOWS;
  uint32_t sp = s->r[widx(w, 14)];
  for(uint32_t i = 0; i < 16; i++) {
    s->r[widx(w, 16 + i)] = ld_mem<uint32_t>(s, 0xa, sp + 4*i);
  }
  s->wim = 1u << ((s->cwp + 2) % NWINDOWS);
}

/* --user: Linux sparc32 syscall ABI.  ta 0x10, number in %g1, args in %o0-%o5,
 * result in %o0, icc.C set on error (with a positive errno in %o0).  The kernel
 * returns to nPC. */
static void emu_syscall(state_t *s) {
  static const uint32_t SPARC_ENOSYS = 90;
  uint32_t num = s->gpr(1);
  uint32_t a0 = s->gpr(8), a1 = s->gpr(9), a2 = s->gpr(10);
  int64_t rc = 0;
  switch(num)
    {
    case 1:     /* exit */
    case 188:   /* exit_group */
      s->brk = true;
      s->exit_code = static_cast<int32_t>(a0);
      break;
    case 4: {   /* write */
      FILE *fp = (a0 == 2) ? stderr : stdout;
      for(uint32_t i = 0; i < a2; i++) {
	fputc(ld_mem<uint8_t>(s, 0xa, a1 + i), fp);
      }
      fflush(fp);
      rc = a2;
      break;
    }
    default:
      fprintf(stderr, "ISS: unimplemented syscall %u at pc 0x%x\n", num, s->pc);
      rc = -static_cast<int64_t>(SPARC_ENOSYS);
      break;
    }
  if(rc < 0) {
    s->gpr(8) = static_cast<uint32_t>(-rc);
    s->icc_c = true;
  }
  else {
    s->gpr(8) = static_cast<uint32_t>(rc);
    s->icc_c = false;
  }
  s->pc = s->npc;
  s->npc = s->npc + 4;
}

/* ---------------------------------------------------------------- integer helpers */

static inline void set_nz(state_t *s, uint32_t res) {
  s->icc_n = (res >> 31) & 1;
  s->icc_z = (res == 0);
}

static inline uint32_t add_cc(state_t *s, uint32_t a, uint32_t b, uint32_t cin) {
  uint64_t sum = static_cast<uint64_t>(a) + b + cin;
  uint32_t res = static_cast<uint32_t>(sum);
  set_nz(s, res);
  s->icc_v = (((~(a ^ b)) & (a ^ res)) >> 31) & 1;
  s->icc_c = (sum >> 32) & 1;
  return res;
}

static inline uint32_t sub_cc(state_t *s, uint32_t a, uint32_t b, uint32_t cin) {
  uint64_t diff = static_cast<uint64_t>(a) - b - cin;
  uint32_t res = static_cast<uint32_t>(diff);
  set_nz(s, res);
  s->icc_v = (((a ^ b) & (a ^ res)) >> 31) & 1;
  s->icc_c = (diff >> 32) & 1;   /* borrow */
  return res;
}

static inline bool eval_icc(const state_t *s, uint32_t cond) {
  bool r = false;
  switch(cond & 7)
    {
    case 0: r = false; break;                                 /* bn   */
    case 1: r = s->icc_z; break;                              /* be   */
    case 2: r = s->icc_z or (s->icc_n != s->icc_v); break;    /* ble  */
    case 3: r = (s->icc_n != s->icc_v); break;                /* bl   */
    case 4: r = s->icc_c or s->icc_z; break;                  /* bleu */
    case 5: r = s->icc_c; break;                              /* bcs  */
    case 6: r = s->icc_n; break;                              /* bneg */
    case 7: r = s->icc_v; break;                              /* bvs  */
    }
  /* conds 8..15 are the complements of 0..7 (ba, bne, bg, ...) */
  return (cond & 8) ? not r : r;
}

/* fcc: 0 '=', 1 '<', 2 '>', 3 unordered.  Bit k of the mask set => taken when fcc==k. */
static bool eval_fcc(uint32_t fcc, uint32_t cond) {
  static const uint8_t mask[16] = {
    0x0, 0xe, 0x6, 0xa, 0x2, 0xc, 0x4, 0x8,
    0xf, 0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7
  };
  return (mask[cond & 15] >> fcc) & 1;
}

/* ---------------------------------------------------------------- FPU */

static inline float  as_f(uint32_t x) { float f; memcpy(&f, &x, 4); return f; }
static inline uint32_t as_u(float f) { uint32_t x; memcpy(&x, &f, 4); return x; }
static inline double as_d(uint64_t x) { double d; memcpy(&d, &x, 8); return d; }
static inline uint64_t as_u(double d) { uint64_t x; memcpy(&x, &d, 8); return x; }

static inline bool nan32(uint32_t x) { return ((x >> 23) & 0xff) == 0xff and (x & 0x7fffff); }
static inline bool snan32(uint32_t x) { return nan32(x) and not (x & 0x400000); }
static inline bool nan64(uint64_t x) { return ((x >> 52) & 0x7ff) == 0x7ff and (x & 0xfffffffffffffULL); }
static inline bool snan64(uint64_t x) { return nan64(x) and not (x & 0x8000000000000ULL); }

static const uint32_t DEFAULT_NAN32 = 0x7fffffffu;
static const uint64_t DEFAULT_NAN64 = 0x7fffffffffffffffULL;

/* SPARC NaN propagation: an SNaN in rs2, else an SNaN in rs1, else a QNaN in
 * rs2, else rs1 -- quieted.  (x86 prefers the first operand, so this is done
 * explicitly rather than trusting the host.) */
static uint32_t pick_nan32(uint32_t a, uint32_t b) {
  if(snan32(b)) {
    return b | 0x400000;
  }
  if(snan32(a)) {
    return a | 0x400000;
  }
  return nan32(b) ? b : a;
}

static uint64_t pick_nan64(uint64_t a, uint64_t b) {
  if(snan64(b)) {
    return b | 0x8000000000000ULL;
  }
  if(snan64(a)) {
    return a | 0x8000000000000ULL;
  }
  return nan64(b) ? b : a;
}

/* use only where the inputs were not NaN: then a NaN result came from an invalid
 * op, and SPARC produces its default NaN rather than the x86 one */
static inline uint32_t def_nan32(uint32_t r) { return nan32(r) ? DEFAULT_NAN32 : r; }
static inline uint64_t def_nan64(uint64_t r) { return nan64(r) ? DEFAULT_NAN64 : r; }

static inline uint64_t get_d(const state_t *s, uint32_t r) {
  r &= ~1u;   /* odd double reg: low bit ignored (hardware behavior, matches qemu) */
  return (static_cast<uint64_t>(s->f[r]) << 32) | s->f[r + 1];
}

static inline void set_d(state_t *s, uint32_t r, uint64_t v) {
  r &= ~1u;
  s->f[r] = static_cast<uint32_t>(v >> 32);
  s->f[r + 1] = static_cast<uint32_t>(v);
}

static void fp_set_round(uint32_t fsr) {
  static const int modes[4] = {FE_TONEAREST, FE_TOWARDZERO, FE_UPWARD, FE_DOWNWARD};
  fesetround(modes[(fsr >> FSR_RD_SHIFT) & 3]);
}

static uint32_t host_exc() {
  int e = fetestexcept(FE_ALL_EXCEPT);
  uint32_t r = 0;
  if(e & FE_INEXACT)   { r |= FEXC_NX; }
  if(e & FE_DIVBYZERO) { r |= FEXC_DZ; }
  if(e & FE_UNDERFLOW) { r |= FEXC_UF; }
  if(e & FE_OVERFLOW)  { r |= FEXC_OF; }
  if(e & FE_INVALID)   { r |= FEXC_NV; }
  return r;
}

static inline void set_ftt(state_t *s, uint32_t ftt) {
  s->fsr = (s->fsr & ~(7u << FSR_FTT_SHIFT)) | (ftt << FSR_FTT_SHIFT);
}

static uint32_t fp_unimp(state_t *s, uint32_t pc, uint32_t inst) {
  set_ftt(s, FTT_UNIMP);
  s->fq_addr = pc;
  s->fq_insn = inst;
  s->fsr |= FSR_QNE;
  return TT_FP_EXCEPTION;
}

/* float -> int32 (fstoi/fdtoi always round toward zero).  NaN and positive
 * overflow give 0x7fffffff, negative overflow 0x80000000, all with NV. */
static uint32_t f2i(double v, uint32_t *exc) {
  if(std::isnan(v) or v >= 2147483648.0) {
    *exc |= FEXC_NV;
    return 0x7fffffffu;
  }
  if(v <= -2147483649.0) {
    *exc |= FEXC_NV;
    return 0x80000000u;
  }
  double t = std::trunc(v);
  if(t != v) {
    *exc |= FEXC_NX;
  }
  return static_cast<uint32_t>(static_cast<int32_t>(t));
}

/* FPop1 / FPop2.  Traps are precise: the trapping FPop is the one in FQ and at
 * the trap PC.
 *
 * TODO(co-sim): x86 detects tininess after rounding; if the RTL FPU detects it
 * before rounding, UF can differ on results right at the denormal boundary. */
static uint32_t exec_fpop(state_t *s, uint32_t pc, uint32_t inst, bool fpop2) {
  uint32_t rd = (inst >> 25) & 31;
  uint32_t rs1 = (inst >> 14) & 31;
  uint32_t rs2 = inst & 31;
  uint32_t opf = (inst >> 5) & 0x1ff;

  enum class dst_t { none, s, d, fcc };
  dst_t dst = dst_t::none;
  uint32_t r32 = 0;
  uint64_t r64 = 0;
  uint32_t exc = 0;

  fp_set_round(s->fsr);
  feclearexcept(FE_ALL_EXCEPT);

  uint32_t a32 = s->f[rs1], b32 = s->f[rs2];
  uint64_t a64 = get_d(s, rs1), b64 = get_d(s, rs2);

  if(fpop2) {
    bool is_e = false;
    bool is_d = false;
    switch(opf)
      {
      case 0x051: break;                            /* fcmps  */
      case 0x052: is_d = true; break;               /* fcmpd  */
      case 0x055: is_e = true; break;               /* fcmpes */
      case 0x056: is_e = true; is_d = true; break;  /* fcmped */
      default:
	return fp_unimp(s, pc, inst);                 /* quad + reserved */
      }
    bool unord = is_d ? (nan64(a64) or nan64(b64)) : (nan32(a32) or nan32(b32));
    bool sig = is_d ? (snan64(a64) or snan64(b64)) : (snan32(a32) or snan32(b32));
    if(sig or (is_e and unord)) {
      exc |= FEXC_NV;
    }
    if(unord) {
      r32 = 3;
    }
    else {
      double x = is_d ? as_d(a64) : as_f(a32);
      double y = is_d ? as_d(b64) : as_f(b32);
      r32 = (x == y) ? 0 : ((x < y) ? 1 : 2);
    }
    dst = dst_t::fcc;
  }
  else {
    switch(opf)
      {
      case 0x001: r32 = b32; dst = dst_t::s; break;                    /* fmovs */
      case 0x005: r32 = b32 ^ 0x80000000u; dst = dst_t::s; break;      /* fnegs */
      case 0x009: r32 = b32 & 0x7fffffffu; dst = dst_t::s; break;      /* fabss */
      case 0x029:                                                       /* fsqrts */
	if(nan32(b32)) {
	  r32 = pick_nan32(b32, b32);
	  exc |= snan32(b32) ? FEXC_NV : 0;
	}
	else {
	  volatile float x = as_f(b32);
	  r32 = def_nan32(as_u(std::sqrt(x)));
	  exc |= host_exc();
	}
	dst = dst_t::s;
	break;
      case 0x02a:                                                       /* fsqrtd */
	if(nan64(b64)) {
	  r64 = pick_nan64(b64, b64);
	  exc |= snan64(b64) ? FEXC_NV : 0;
	}
	else {
	  volatile double x = as_d(b64);
	  r64 = def_nan64(as_u(std::sqrt(x)));
	  exc |= host_exc();
	}
	dst = dst_t::d;
	break;
      case 0x041: case 0x045: case 0x049: case 0x04d:                   /* fadds fsubs fmuls fdivs */
	if(nan32(a32) or nan32(b32)) {
	  r32 = pick_nan32(a32, b32);
	  exc |= (snan32(a32) or snan32(b32)) ? FEXC_NV : 0;
	}
	else {
	  volatile float x = as_f(a32), y = as_f(b32);
	  float z = (opf == 0x041) ? x + y : (opf == 0x045) ? x - y : (opf == 0x049) ? x * y : x / y;
	  r32 = def_nan32(as_u(z));
	  exc |= host_exc();
	}
	dst = dst_t::s;
	break;
      case 0x042: case 0x046: case 0x04a: case 0x04e:                   /* faddd fsubd fmuld fdivd */
	if(nan64(a64) or nan64(b64)) {
	  r64 = pick_nan64(a64, b64);
	  exc |= (snan64(a64) or snan64(b64)) ? FEXC_NV : 0;
	}
	else {
	  volatile double x = as_d(a64), y = as_d(b64);
	  double z = (opf == 0x042) ? x + y : (opf == 0x046) ? x - y : (opf == 0x04a) ? x * y : x / y;
	  r64 = def_nan64(as_u(z));
	  exc |= host_exc();
	}
	dst = dst_t::d;
	break;
      case 0x069:                                                       /* fsmuld (exact) */
	if(nan32(a32) or nan32(b32)) {
	  volatile float n = as_f(pick_nan32(a32, b32));
	  r64 = as_u(static_cast<double>(n));
	  exc |= (snan32(a32) or snan32(b32)) ? FEXC_NV : 0;
	}
	else {
	  volatile double x = as_f(a32), y = as_f(b32);
	  r64 = def_nan64(as_u(x * y));
	  exc |= host_exc();
	}
	dst = dst_t::d;
	break;
      case 0x0c4: {                                                     /* fitos */
	volatile int32_t x = static_cast<int32_t>(b32);
	r32 = as_u(static_cast<float>(x));
	exc |= host_exc();
	dst = dst_t::s;
	break;
      }
      case 0x0c8: {                                                     /* fitod (exact) */
	volatile int32_t x = static_cast<int32_t>(b32);
	r64 = as_u(static_cast<double>(x));
	dst = dst_t::d;
	break;
      }
      case 0x0c9: {                                                     /* fstod */
	/* the host widen quiets an SNaN, keeps the payload and raises NV: same as V8 */
	volatile float x = as_f(b32);
	r64 = as_u(static_cast<double>(x));
	exc |= host_exc();
	dst = dst_t::d;
	break;
      }
      case 0x0c6: {                                                     /* fdtos */
	volatile double x = as_d(b64);
	r32 = as_u(static_cast<float>(x));
	exc |= host_exc();
	dst = dst_t::s;
	break;
      }
      case 0x0d1:                                                       /* fstoi */
	r32 = f2i(as_f(b32), &exc);
	dst = dst_t::s;
	break;
      case 0x0d2:                                                       /* fdtoi */
	r32 = f2i(as_d(b64), &exc);
	dst = dst_t::s;
	break;
      default:
	return fp_unimp(s, pc, inst);                                   /* quad + reserved */
      }
  }

  uint32_t tem = (s->fsr >> FSR_TEM_SHIFT) & 0x1f;
  s->fsr = (s->fsr & ~0x1fu) | exc;   /* cexc */
  if(exc & tem) {
    /* IEEE trap: cexc updated, aexc and the destination untouched */
    set_ftt(s, FTT_IEEE);
    s->fq_addr = pc;
    s->fq_insn = inst;
    s->fsr |= FSR_QNE;
    return TT_FP_EXCEPTION;
  }
  set_ftt(s, 0);
  s->fsr |= exc << FSR_AEXC_SHIFT;
  switch(dst)
    {
    case dst_t::s:
      s->f[rd] = r32;
      break;
    case dst_t::d:
      set_d(s, rd, r64);
      break;
    case dst_t::fcc:
      s->fsr = (s->fsr & ~(3u << FSR_FCC_SHIFT)) | (r32 << FSR_FCC_SHIFT);
      break;
    default:
      break;
    }
  return NO_TRAP;
}

/* ---------------------------------------------------------------- execute */

void take_interrupt(state_t *s, uint32_t level) {
  take_trap(s, TT_INTERRUPT_BASE + level);
}

/* every instruction the per-op handlers do not finish: the full semantics,
 * traps included.  inst was fetched from s->pc; nothing has changed yet. */
static __attribute__((noinline)) void exec_slow(state_t *s, uint32_t inst) {
  const uint32_t pc = s->pc;
  const uint32_t npc = s->npc;

  uint32_t new_pc = npc;
  uint32_t new_npc = npc + 4;
  uint32_t trap = NO_TRAP;

  const uint32_t op = inst >> 30;
  const uint32_t rd = (inst >> 25) & 31;
  const uint32_t op3 = (inst >> 19) & 63;
  const uint32_t rs1 = (inst >> 14) & 31;
  const bool imm = (inst >> 13) & 1;
  const uint32_t simm13 = static_cast<uint32_t>(static_cast<int32_t>(inst << 19) >> 19);

  /* writes to %g0 are discarded */
  auto wr = [&](uint32_t r, uint32_t v) {
    if(r != 0) {
      s->gpr(r) = v;
    }
  };

  switch(op)
    {
    case 0: {
      const uint32_t op2 = (inst >> 22) & 7;
      const uint32_t cond = (inst >> 25) & 15;
      const bool annul = (inst >> 29) & 1;
      const uint32_t tgt = pc + (static_cast<uint32_t>(static_cast<int32_t>(inst << 10) >> 10) << 2);
      if(op2 == 4) {             /* sethi (rd=0, imm=0 is nop) */
	wr(rd, inst << 10);
	break;
      }
      if(op2 == 7) {             /* CBccc */
	trap = TT_CP_DISABLED;
	break;
      }
      if(op2 != 2 and op2 != 6) { /* unimp + the V9 encodings */
	trap = TT_ILLEGAL;
	break;
      }
      if(op2 == 6 and not s->ef) {
	trap = TT_FP_DISABLED;
	break;
      }
      bool taken = (op2 == 2) ? eval_icc(s, cond) : eval_fcc((s->fsr >> FSR_FCC_SHIFT) & 3, cond);
      if(cond == 8) {            /* ba / fba: the annul bit kills the delay slot */
	if(annul) {
	  new_pc = tgt;
	  new_npc = tgt + 4;
	}
	else {
	  new_npc = tgt;
	}
      }
      else if(taken) {
	new_npc = tgt;
      }
      else if(annul) {           /* not taken + annul: skip the delay slot */
	new_pc = npc + 4;
	new_npc = npc + 8;
      }
      break;
    }
    case 1:                      /* call */
      wr(15, pc);
      new_npc = pc + (inst << 2);
      break;
    case 2: {
      const uint32_t a = s->gpr(rs1);
      const uint32_t b = imm ? simm13 : s->gpr(inst & 31);
      switch(op3)
	{
	case 0x00: wr(rd, a + b); break;                                  /* add  */
	case 0x01: wr(rd, a & b); break;                                  /* and  */
	case 0x02: wr(rd, a | b); break;                                  /* or   */
	case 0x03: wr(rd, a ^ b); break;                                  /* xor  */
	case 0x04: wr(rd, a - b); break;                                  /* sub  */
	case 0x05: wr(rd, a & ~b); break;                                 /* andn */
	case 0x06: wr(rd, a | ~b); break;                                 /* orn  */
	case 0x07: wr(rd, ~(a ^ b)); break;                               /* xnor */
	case 0x08: wr(rd, a + b + s->icc_c); break;                       /* addx */
	case 0x0c: wr(rd, a - b - s->icc_c); break;                       /* subx */
	case 0x10: wr(rd, add_cc(s, a, b, 0)); break;                     /* addcc */
	case 0x14: wr(rd, sub_cc(s, a, b, 0)); break;                     /* subcc */
	case 0x18: wr(rd, add_cc(s, a, b, s->icc_c)); break;              /* addxcc */
	case 0x1c: wr(rd, sub_cc(s, a, b, s->icc_c)); break;              /* subxcc */
	case 0x11: case 0x12: case 0x13:                                  /* andcc orcc xorcc */
	case 0x15: case 0x16: case 0x17: {                                /* andncc orncc xnorcc */
	  uint32_t res = 0;
	  switch(op3 & 7)
	    {
	    case 1: res = a & b; break;
	    case 2: res = a | b; break;
	    case 3: res = a ^ b; break;
	    case 5: res = a & ~b; break;
	    case 6: res = a | ~b; break;
	    case 7: res = ~(a ^ b); break;
	    default: UNREACHABLE();
	    }
	  set_nz(s, res);
	  s->icc_v = false;
	  s->icc_c = false;
	  wr(rd, res);
	  break;
	}
	case 0x0a: case 0x0b: case 0x1a: case 0x1b: {                     /* umul smul umulcc smulcc */
	  uint64_t p = (op3 & 1) ?
	    static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(a)) * static_cast<int32_t>(b)) :
	    static_cast<uint64_t>(a) * b;
	  s->y = static_cast<uint32_t>(p >> 32);
	  if(op3 & 0x10) {
	    set_nz(s, static_cast<uint32_t>(p));
	    s->icc_v = false;
	    s->icc_c = false;
	  }
	  wr(rd, static_cast<uint32_t>(p));
	  break;
	}
	case 0x0e: case 0x0f: case 0x1e: case 0x1f: {                     /* udiv sdiv udivcc sdivcc */
	  if(b == 0) {
	    trap = TT_DIV_ZERO;
	    break;
	  }
	  uint64_t dividend = (static_cast<uint64_t>(s->y) << 32) | a;
	  uint32_t q = 0;
	  bool ovf = false;
	  if(op3 & 1) {
	    int64_t n = static_cast<int64_t>(dividend);
	    int64_t d = static_cast<int32_t>(b);
	    if(n == INT64_MIN and d == -1) {
	      q = 0x7fffffffu;
	      ovf = true;
	    }
	    else {
	      int64_t t = n / d;
	      if(t > INT32_MAX) {
		q = 0x7fffffffu;
		ovf = true;
	      }
	      else if(t < INT32_MIN) {
		q = 0x80000000u;
		ovf = true;
	      }
	      else {
		q = static_cast<uint32_t>(t);
	      }
	    }
	  }
	  else {
	    uint64_t t = dividend / b;
	    if(t > 0xffffffffULL) {
	      q = 0xffffffffu;
	      ovf = true;
	    }
	    else {
	      q = static_cast<uint32_t>(t);
	    }
	  }
	  if(op3 & 0x10) {
	    set_nz(s, q);
	    s->icc_v = ovf;
	    s->icc_c = false;
	  }
	  wr(rd, q);
	  break;
	}
	case 0x20: case 0x21: case 0x22: case 0x23: {                     /* taddcc tsubcc taddcctv tsubcctv */
	  bool is_sub = op3 & 1;
	  uint32_t res = is_sub ? a - b : a + b;
	  bool v = is_sub ? ((((a ^ b) & (a ^ res)) >> 31) & 1) : ((((~(a ^ b)) & (a ^ res)) >> 31) & 1);
	  v = v or ((a | b) & 3);
	  if((op3 & 2) and v) {
	    trap = TT_TAG_OVERFLOW;   /* tv forms: no register or icc update */
	    break;
	  }
	  if(is_sub) {
	    sub_cc(s, a, b, 0);
	  }
	  else {
	    add_cc(s, a, b, 0);
	  }
	  s->icc_v = v;
	  wr(rd, res);
	  break;
	}
	case 0x24: {                                                      /* mulscc */
	  uint32_t op1 = (static_cast<uint32_t>(s->icc_n != s->icc_v) << 31) | (a >> 1);
	  uint32_t op2v = (s->y & 1) ? b : 0;
	  uint32_t res = add_cc(s, op1, op2v, 0);
	  s->y = ((a & 1) << 31) | (s->y >> 1);
	  wr(rd, res);
	  break;
	}
	case 0x25: wr(rd, a << (b & 31)); break;                                                     /* sll */
	case 0x26: wr(rd, a >> (b & 31)); break;                                                     /* srl */
	case 0x27: wr(rd, static_cast<uint32_t>(static_cast<int32_t>(a) >> (b & 31))); break;       /* sra */
	case 0x28:                                                        /* rdy / stbar / rdasr */
	  /* as qemu sparc32 (non-LEON): rs1 = 15 is stbar whatever rd is, and every
	   * other rs1 reads %y (V8: rs1 1..14 are undefined but must not trap, 16..31
	   * implementation-dependent; SuperSPARC implements no ASRs) */
	  if(rs1 == 15) {
	    /* stbar: stores are already in order here */
	  }
	  else {
	    wr(rd, s->y);
	  }
	  break;
	case 0x29: case 0x2a: case 0x2b:                                  /* rdpsr rdwim rdtbr */
	  if(not s->s) {
	    trap = TT_PRIVILEGED;
	    break;
	  }
	  wr(rd, (op3 == 0x29) ? s->get_psr() : (op3 == 0x2a) ? s->wim : s->tbr);
	  break;
	case 0x30:                                                        /* wry / wrasr (note: xor) */
	  if(rd == 0) {
	    s->y = a ^ b;
	  }
	  /* wr %asrN, N != 0: a nop, as qemu sparc32 (non-LEON) */
	  break;
	case 0x31: case 0x32: case 0x33: {                                /* wrpsr wrwim wrtbr */
	  if(not s->s) {
	    trap = TT_PRIVILEGED;
	    break;
	  }
	  uint32_t v = a ^ b;
	  if(op3 == 0x31) {
	    if((v & 31) >= NWINDOWS) {
	      trap = TT_ILLEGAL;
	      break;
	    }
	    s->set_psr(v);
	  }
	  else if(op3 == 0x32) {
	    s->wim = v & ((1u << NWINDOWS) - 1);
	  }
	  else {
	    s->tbr = (v & 0xfffff000u) | (s->tbr & 0xff0u);
	  }
	  break;
	}
	case 0x34: case 0x35:                                             /* FPop1 FPop2 */
	  if(not s->ef) {
	    trap = TT_FP_DISABLED;
	    break;
	  }
	  trap = exec_fpop(s, pc, inst, op3 == 0x35);
	  break;
	case 0x36: case 0x37:                                             /* CPop */
	  trap = TT_CP_DISABLED;
	  break;
	case 0x38: {                                                      /* jmpl */
	  uint32_t tgt = a + b;
	  if(tgt & 3) {
	    trap = TT_UNALIGNED;
	    break;
	  }
	  wr(rd, pc);
	  new_npc = tgt;
	  break;
	}
	case 0x39: {                                                      /* rett */
	  uint32_t tgt = a + b;
	  uint32_t ncwp = (s->cwp + 1) % NWINDOWS;
	  if(s->et) {
	    trap = s->s ? TT_ILLEGAL : TT_PRIVILEGED;
	    break;
	  }
	  /* ET=0: any of these is a trap with ET=0, i.e. error mode */
	  if(not s->s) {
	    trap = TT_PRIVILEGED;
	    break;
	  }
	  if((s->wim >> ncwp) & 1) {
	    trap = TT_WIN_UNDERFLOW;
	    break;
	  }
	  if(tgt & 3) {
	    trap = TT_UNALIGNED;
	    break;
	  }
	  s->cwp = ncwp;
	  s->et = true;
	  s->set_s(s->ps);
	  new_npc = tgt;
	  break;
	}
	case 0x3a:                                                        /* ticc */
	  if(eval_icc(s, (inst >> 25) & 15)) {
	    trap = TT_TRAP_INSN_BASE + ((a + b) & 0x7f);
	  }
	  break;
	case 0x3b:                                                        /* flush: no I-cache to keep coherent */
	  break;
	case 0x3c: case 0x3d: {                                           /* save restore */
	  bool is_save = (op3 == 0x3c);
	  uint32_t ncwp = is_save ? (s->cwp + NWINDOWS - 1) % NWINDOWS : (s->cwp + 1) % NWINDOWS;
	  if((s->wim >> ncwp) & 1) {
	    if(not s->user_emu) {
	      trap = is_save ? TT_WIN_OVERFLOW : TT_WIN_UNDERFLOW;
	      break;
	    }
	    if(is_save) {
	      emu_spill(s);
	    }
	    else {
	      emu_fill(s);
	    }
	  }
	  /* sources read in the old window, rd written in the new one */
	  s->cwp = ncwp;
	  wr(rd, a + b);
	  break;
	}
	default:
	  trap = TT_ILLEGAL;
	  break;
	}
      break;
    }
    case 3: {
      const uint32_t a = s->gpr(rs1);
      if(op3 == 0x3c) {
	/* casa [rs1] asi, rs2, rd: LEON3's V8 CASA in V9's encoding, which Kodiak
	 * implements (superdupersparc interpret.cc has the same rules).  The word
	 * at [rs1] is compared with rs2; if they are equal rd is written there;
	 * either way rd gets the old word.
	 *   - supervisor only, except ASI 0xa (user data) with i = 0, as LEON3
	 *   - i = 1 (V9's %asi form) or a non-memory ASI is illegal
	 *   - cacheable memory only (RAM, MCR.DE, the PTE's C with the MMU on,
	 *     MCR.AC with it off, never a bypass ASI): Kodiak's memory side cannot
	 *     compare, so an uncached casa takes data_access_error with no access
	 *     and no fault-status record */
	const uint32_t asi = (inst >> 5) & 0xff;
	if(not s->s and (imm or asi != 0xa)) {
	  trap = TT_PRIVILEGED;
	  break;
	}
	if(imm or not asi_is_memory(asi)) {
	  trap = TT_ILLEGAL;
	  break;
	}
	if(a & 3) {
	  trap = TT_UNALIGNED;
	  break;
	}
	uint64_t pa = 0;
	uint32_t pte = 0;
	if(mmu_xlate_slow(s, asi, a, acc_t::store, &pa, &pte) != FT_NONE) {
	  if(not (s->mmu_ctrl & MCR_NF)) {
	    trap = TT_DACCESS;
	  }
	  break;
	}
	const bool c = asi_is_bypass(asi) ? false : (s->mmu_ctrl & MCR_E) ? (((pte >> 7) & 1) != 0) :
	  ((s->mmu_ctrl & (1u << 15)) != 0);                 /* Viking MCR.AC */
	if(not c or not (s->mmu_ctrl & (1u << 8)) or (pa >= s->ram_size)) {   /* MCR.DE */
	  trap = TT_DACCESS_ERROR;
	  break;
	}
	const uint32_t old = ld_phys<uint32_t>(s, pa);
	st_phys<uint32_t>(s, pa, (old == s->gpr(inst & 31)) ? s->gpr(rd) : old);
	wr(rd, old);
	break;
      }
      const uint32_t addr = a + (imm ? simm13 : s->gpr(inst & 31));
      uint32_t asi = s->s ? 0xb : 0xa;
      const bool is_int = (op3 < 0x20);
      const bool is_alt = is_int and (op3 & 0x10);
      if(is_alt) {                            /* alternate space */
	if(not s->s) {
	  trap = TT_PRIVILEGED;
	  break;
	}
	if(imm) {
	  trap = TT_ILLEGAL;
	  break;
	}
	asi = (inst >> 5) & 0xff;
      }
      if(not is_int) {
	if(op3 >= 0x30) {
	  bool cp = (op3 <= 0x37) and (op3 != 0x32);
	  trap = cp ? TT_CP_DISABLED : TT_ILLEGAL;
	  break;
	}
	if(op3 == 0x22 or op3 >= 0x28) {
	  trap = TT_ILLEGAL;
	  break;
	}
	if(op3 == 0x26 and not s->s) {           /* stdfq is privileged */
	  trap = TT_PRIVILEGED;
	  break;
	}
	if(not s->ef) {
	  trap = TT_FP_DISABLED;
	  break;
	}
      }
      const uint32_t base_op = is_int ? (op3 & 0xf) : op3;
      uint32_t sz = 4;
      switch(base_op)
	{
	case 0x01: case 0x05: case 0x09: case 0x0d:
	  sz = 1;
	  break;
	case 0x02: case 0x06: case 0x0a:
	  sz = 2;
	  break;
	case 0x03: case 0x07: case 0x23: case 0x26: case 0x27:
	  sz = 8;
	  break;
	default:
	  break;
	}
      if(is_int and (base_op == 0x08 or base_op == 0x0b or base_op == 0x0c or base_op == 0x0e)) {
	trap = TT_ILLEGAL;                    /* V9 ldsw/ldx/stx/casa encodings */
	break;
      }
      if(is_int and (base_op == 0x03 or base_op == 0x07) and (rd & 1)) {
	trap = TT_ILLEGAL;                    /* ldd/std with an odd rd */
	break;
      }
      if(addr & (sz - 1)) {
	trap = TT_UNALIGNED;
	break;
      }
      const bool is_store = (base_op == 0x04 or base_op == 0x05 or base_op == 0x06 or base_op == 0x07 or
			     base_op == 0x0d or base_op == 0x0f or (base_op >= 0x24 and base_op <= 0x27));
      const bool mem = asi_is_memory(asi);
      uint64_t pa = 0;
      if(mem and mmu_xlate(s, asi, addr, is_store ? acc_t::store : acc_t::load, &pa) != FT_NONE) {
	/* MCR.NF: the fault is recorded but does not trap (the access is dropped) */
	if(not (s->mmu_ctrl & MCR_NF)) {
	  trap = TT_DACCESS;
	}
	break;
      }
      /* what a load may write, for a bus error's precise trap (below) */
      const uint32_t sv_r0 = s->gpr(rd), sv_r1 = s->gpr(rd ^ 1u);
      const uint32_t sv_f0 = s->f[rd], sv_f1 = s->f[rd ^ 1u], sv_fsr = s->fsr;
      /* off = byte offset within the (single-page, naturally aligned) access */
      auto ld32 = [&](uint32_t off) -> uint32_t {
	return mem ? ld_phys<uint32_t>(s, pa + off) : asi_load(s, asi, addr + off);
      };
      auto st32 = [&](uint32_t off, uint32_t v) {
	if(mem) {
	  st_phys<uint32_t>(s, pa + off, v);
	}
	else {
	  asi_store(s, asi, addr + off, v);
	}
      };
      auto ld8 = [&]() -> uint8_t {
	return mem ? ld_phys<uint8_t>(s, pa) : static_cast<uint8_t>(asi_load(s, asi, addr));
      };
      auto ld16 = [&]() -> uint16_t {
	return mem ? ld_phys<uint16_t>(s, pa) : static_cast<uint16_t>(asi_load(s, asi, addr));
      };
      auto st8 = [&](uint8_t v) {
	if(mem) {
	  st_phys<uint8_t>(s, pa, v);
	}
	else {
	  asi_store(s, asi, addr, v);
	}
      };
      auto st16 = [&](uint16_t v) {
	if(mem) {
	  st_phys<uint16_t>(s, pa, v);
	}
	else {
	  asi_store(s, asi, addr, v);
	}
      };
      switch(base_op)
	{
	case 0x00: wr(rd, ld32(0)); break;                                                 /* ld   */
	case 0x01: wr(rd, ld8()); break;                                                   /* ldub */
	case 0x02: wr(rd, ld16()); break;                                                  /* lduh */
	case 0x09: wr(rd, static_cast<uint32_t>(static_cast<int8_t>(ld8()))); break;       /* ldsb */
	case 0x0a: wr(rd, static_cast<uint32_t>(static_cast<int16_t>(ld16()))); break;     /* ldsh */
	case 0x03: {                                                                       /* ldd  */
	  uint32_t hi = ld32(0);
	  uint32_t lo = ld32(4);
	  wr(rd, hi);
	  wr(rd + 1, lo);
	  break;
	}
	case 0x04: st32(0, s->gpr(rd)); break;                                             /* st   */
	case 0x05: st8(static_cast<uint8_t>(s->gpr(rd))); break;                           /* stb  */
	case 0x06: st16(static_cast<uint16_t>(s->gpr(rd))); break;                         /* sth  */
	case 0x07:                                                                         /* std  */
	  st32(0, s->gpr(rd));
	  st32(4, s->gpr(rd + 1));
	  break;
	case 0x0d: {                                                                       /* ldstub */
	  uint8_t v = ld8();
	  st8(0xff);
	  wr(rd, v);
	  break;
	}
	case 0x0f: {                                                                       /* swap */
	  uint32_t v = ld32(0);
	  st32(0, s->gpr(rd));
	  wr(rd, v);
	  break;
	}
	case 0x20: s->f[rd] = ld32(0); break;                                              /* ldf   */
	case 0x21: {                                                                       /* ldfsr */
	  uint32_t v = ld32(0);
	  s->fsr = (s->fsr & ~FSR_LDFSR_MASK) | (v & FSR_LDFSR_MASK);
	  break;
	}
	case 0x23:                                                                         /* lddf  */
	  set_d(s, rd, (static_cast<uint64_t>(ld32(0)) << 32) | ld32(4));
	  break;
	case 0x24: st32(0, s->f[rd]); break;                                               /* stf   */
	case 0x25: st32(0, s->fsr); break;                                                 /* stfsr */
	case 0x26:                                                                         /* stdfq */
	  st32(0, s->fq_addr);
	  st32(4, s->fq_insn);
	  s->fsr &= ~FSR_QNE;
	  break;
	case 0x27:                                                                         /* stdf  */
	  st32(0, s->f[rd & ~1u]);
	  st32(4, s->f[rd | 1u]);
	  break;
	default:
	  trap = TT_ILLEGAL;
	  break;
	}
      if(s->bus_error and mmu_bus_error(s, pa, is_store, false, is_alt)) {
	/* data_access_error is precise: the trapping load writes no register
	 * (qemu raises it before the write-back; the RTL never retires it).  The
	 * op ran with the faulting part reading 0, so put back what it wrote; a
	 * device store that bus-errors was dropped by the device */
	if(rd != 0) {
	  s->gpr(rd) = sv_r0;
	}
	if((rd ^ 1u) != 0) {
	  s->gpr(rd ^ 1u) = sv_r1;
	}
	s->f[rd] = sv_f0;
	s->f[rd ^ 1u] = sv_f1;
	s->fsr = sv_fsr;
	trap = TT_DACCESS_ERROR;
      }
      break;
    }
    }

  if(trap != NO_TRAP) {
    /* s->pc/npc still name the trapping insn: %l1/%l2 get PC/nPC of it */
    if(s->user_emu and trap == TT_TRAP_INSN_BASE + 0x10) {
      s->icnt++;
      emu_syscall(s);
      return;
    }
    take_trap(s, trap);
    return;
  }
  s->icnt++;
  s->pc = new_pc;
  s->npc = new_npc;
}

/* ---- per-op handlers (indysim's predecode: one indirect dispatch per insn) --
 * The common instructions whose every precondition holds -- no trap, no
 * window spill/fill, a load/store that hits the soft TLB and lands in RAM --
 * finish in their own small handler, with the opcode-level choices (op3, the
 * i bit, the branch condition) made once by decode_insn and baked into the
 * template.  A handler whose run-time precondition fails calls exec_slow
 * before changing any state, and exec_slow does the whole instruction (it is
 * the reference: these are its cases, specialised). */
static inline void retire_fast(state_t *s, uint32_t new_pc, uint32_t new_npc) {
  s->icnt++;
  s->pc = new_pc;
  s->npc = new_npc;
}

static inline void wr_fast(state_t *s, uint32_t r, uint32_t v) {
  if(r != 0) {
    s->gpr(r) = v;
  }
}

static inline uint32_t simm13_of(uint32_t inst) {
  return static_cast<uint32_t>(static_cast<int32_t>(inst << 19) >> 19);
}

static void op_sethi(state_t *s, uint32_t inst) {
  wr_fast(s, (inst >> 25) & 31, inst << 10);
  retire_fast(s, s->npc, s->npc + 4);
}

/* nop = sethi 0,%g0: op_sethi plus the user-mode nop counts.  DS = the word
 * before it is a CTI, i.e. it is that CTI's delay slot (fill_slot decides) */
template <bool DS>
static void op_nop(state_t *s, uint32_t) {
  if(not s->s) {
    s->unop++;
    if(DS) {
      s->unop_ds++;
    }
  }
  retire_fast(s, s->npc, s->npc + 4);
}

static inline bool is_cti(uint32_t inst) {
  const uint32_t op = inst >> 30;
  const uint32_t op2 = (inst >> 22) & 7;
  const uint32_t op3 = (inst >> 19) & 0x3f;
  return (op == 1) or ((op == 0) and ((op2 == 2) or (op2 == 6) or (op2 == 7))) or
    ((op == 2) and ((op3 == 0x38) or (op3 == 0x39)));
}

template <uint32_t COND>
static void op_bicc(state_t *s, uint32_t inst) {
  const uint32_t pc = s->pc;
  const uint32_t npc = s->npc;
  const bool annul = (inst >> 29) & 1;
  const uint32_t tgt = pc + (static_cast<uint32_t>(static_cast<int32_t>(inst << 10) >> 10) << 2);
  if(COND == 8) {
    if(annul) {
      retire_fast(s, tgt, tgt + 4);
    }
    else {
      retire_fast(s, npc, tgt);
    }
  }
  else if(eval_icc(s, COND)) {
    retire_fast(s, npc, tgt);
  }
  else if(annul) {
    retire_fast(s, npc + 4, npc + 8);
  }
  else {
    retire_fast(s, npc, npc + 4);
  }
}

static void op_call(state_t *s, uint32_t inst) {
  const uint32_t pc = s->pc;
  wr_fast(s, 15, pc);
  retire_fast(s, s->npc, pc + (inst << 2));
}

template <uint32_t OP3, bool IMM>
static void op_alu(state_t *s, uint32_t inst) {
  const uint32_t a = s->gpr((inst >> 14) & 31);
  const uint32_t b = IMM ? simm13_of(inst) : s->gpr(inst & 31);
  uint32_t v;
  switch(OP3)
    {
    case 0x00: v = a + b; break;
    case 0x01: v = a & b; break;
    case 0x02: v = a | b; break;
    case 0x03: v = a ^ b; break;
    case 0x04: v = a - b; break;
    case 0x05: v = a & ~b; break;
    case 0x06: v = a | ~b; break;
    case 0x07: v = ~(a ^ b); break;
    case 0x10: v = add_cc(s, a, b, 0); break;
    case 0x14: v = sub_cc(s, a, b, 0); break;
    case 0x11: case 0x12: case 0x13: case 0x15: case 0x16: case 0x17:
      v = (OP3 & 7) == 1 ? (a & b) : (OP3 & 7) == 2 ? (a | b) : (OP3 & 7) == 3 ? (a ^ b) :
	(OP3 & 7) == 5 ? (a & ~b) : (OP3 & 7) == 6 ? (a | ~b) : ~(a ^ b);
      set_nz(s, v);
      s->icc_v = false;
      s->icc_c = false;
      break;
    case 0x25: v = a << (b & 31); break;
    case 0x26: v = a >> (b & 31); break;
    case 0x27: v = static_cast<uint32_t>(static_cast<int32_t>(a) >> (b & 31)); break;
    default:
      UNREACHABLE();
    }
  wr_fast(s, (inst >> 25) & 31, v);
  retire_fast(s, s->npc, s->npc + 4);
}

template <bool IMM>
static void op_jmpl(state_t *s, uint32_t inst) {
  const uint32_t tgt = s->gpr((inst >> 14) & 31) + (IMM ? simm13_of(inst) : s->gpr(inst & 31));
  if(tgt & 3) {
    exec_slow(s, inst);
    return;
  }
  const uint32_t pc = s->pc;
  wr_fast(s, (inst >> 25) & 31, pc);
  retire_fast(s, s->npc, tgt);
}

/* save / restore without a window trap: the sources are read in the old
 * window, rd is written in the new one */
template <bool SAVE, bool IMM>
static void op_saverestore(state_t *s, uint32_t inst) {
  const uint32_t ncwp = SAVE ? (s->cwp + NWINDOWS - 1) % NWINDOWS : (s->cwp + 1) % NWINDOWS;
  if((s->wim >> ncwp) & 1) {
    exec_slow(s, inst);
    return;
  }
  const uint32_t v = s->gpr((inst >> 14) & 31) + (IMM ? simm13_of(inst) : s->gpr(inst & 31));
  s->cwp = ncwp;
  wr_fast(s, (inst >> 25) & 31, v);
  retire_fast(s, s->npc, s->npc + 4);
}

/* integer ld/st: ld ldub lduh ldd st stb sth std ldsb ldsh, and their
 * alternate-space forms (supervisor, register address: decode_insn sends the
 * i = 1 forms, and ldd/std with an odd rd, to exec_slow) through the bypass
 * ASIs or a translated ASI that hits the soft TLB, to RAM */
static constexpr uint8_t LDST_SZ[16] = {4, 1, 2, 8, 4, 1, 2, 8, 0, 1, 2, 0, 0, 0, 0, 0};

template <uint32_t OP3, bool IMM>
static void op_ldst(state_t *s, uint32_t inst) {
  constexpr uint32_t sz = LDST_SZ[OP3 & 0xf];
  constexpr bool is_alt = OP3 & 0x10;
  constexpr bool is_store = (OP3 & 0xc) == 0x4;
  const uint32_t rd = (inst >> 25) & 31;
  if(is_alt and not s->s) {
    exec_slow(s, inst);
    return;
  }
  const uint32_t addr = s->gpr((inst >> 14) & 31) + (IMM ? simm13_of(inst) : s->gpr(inst & 31));
  if(addr & (sz - 1)) {
    exec_slow(s, inst);
    return;
  }
  const uint32_t asi = is_alt ? ((inst >> 5) & 0xff) : (s->s ? 0xb : 0xa);
  uint64_t pa;
  if(asi_is_bypass(asi)) {
    pa = (static_cast<uint64_t>(asi & 0xf) << 32) | addr;
  }
  else if(asi > 0xb or asi < 0x8 or not stlb_hit(s, asi, addr, is_store ? acc_t::store : acc_t::load, &pa)) {
    exec_slow(s, inst);
    return;
  }
  if(pa + sz > s->ram_size) {
    exec_slow(s, inst);
    return;
  }
  if(is_store) {
    code_write_check(pa);
  }
  dma_race_access(s, pa, is_store);
  switch(OP3 & 0xf)
    {
    case 0x00: wr_fast(s, rd, be(s->mem.get<uint32_t>(pa))); break;
    case 0x01: wr_fast(s, rd, s->mem.get<uint8_t>(pa)); break;
    case 0x02: wr_fast(s, rd, be(s->mem.get<uint16_t>(pa))); break;
    case 0x09: wr_fast(s, rd, static_cast<uint32_t>(static_cast<int8_t>(s->mem.get<uint8_t>(pa)))); break;
    case 0x0a: wr_fast(s, rd, static_cast<uint32_t>(static_cast<int16_t>(be(s->mem.get<uint16_t>(pa))))); break;
    case 0x03: {
      const uint32_t hi = be(s->mem.get<uint32_t>(pa));
      const uint32_t lo = be(s->mem.get<uint32_t>(pa + 4));
      wr_fast(s, rd, hi);
      wr_fast(s, rd + 1, lo);
      break;
    }
    case 0x04: s->mem.set<uint32_t>(pa, be(s->gpr(rd))); break;
    case 0x05: s->mem.set<uint8_t>(pa, static_cast<uint8_t>(s->gpr(rd))); break;
    case 0x06: s->mem.set<uint16_t>(pa, be(static_cast<uint16_t>(s->gpr(rd)))); break;
    case 0x07:
      s->mem.set<uint32_t>(pa, be(s->gpr(rd)));
      s->mem.set<uint32_t>(pa + 4, be(s->gpr(rd + 1)));
      break;
    default:
      UNREACHABLE();
    }
  retire_fast(s, s->npc, s->npc + 4);
}

/* ---- decode: the handler for an instruction word ------------------------- */
typedef void (*dinst_fn_t)(state_t *s, uint32_t inst);

#define DEC_IMM(H, ...) return imm ? H<__VA_ARGS__, true> : H<__VA_ARGS__, false>

static dinst_fn_t decode_insn(uint32_t inst) {
  static const dinst_fn_t BICC[16] = {
    op_bicc<0>, op_bicc<1>, op_bicc<2>, op_bicc<3>, op_bicc<4>, op_bicc<5>, op_bicc<6>, op_bicc<7>,
    op_bicc<8>, op_bicc<9>, op_bicc<10>, op_bicc<11>, op_bicc<12>, op_bicc<13>, op_bicc<14>, op_bicc<15>
  };
  const bool imm = (inst >> 13) & 1;
  const uint32_t op3 = (inst >> 19) & 63;
  switch(inst >> 30)
    {
    case 0: {
      const uint32_t op2 = (inst >> 22) & 7;
      if(op2 == 4) {
	return op_sethi;
      }
      if(op2 == 2) {
	return BICC[(inst >> 25) & 15];
      }
      return exec_slow;                                  /* FBfcc, CBccc, unimp */
    }
    case 1:
      return op_call;
    case 2:
      switch(op3)
	{
	case 0x00: DEC_IMM(op_alu, 0x00);
	case 0x01: DEC_IMM(op_alu, 0x01);
	case 0x02: DEC_IMM(op_alu, 0x02);
	case 0x03: DEC_IMM(op_alu, 0x03);
	case 0x04: DEC_IMM(op_alu, 0x04);
	case 0x05: DEC_IMM(op_alu, 0x05);
	case 0x06: DEC_IMM(op_alu, 0x06);
	case 0x07: DEC_IMM(op_alu, 0x07);
	case 0x10: DEC_IMM(op_alu, 0x10);
	case 0x11: DEC_IMM(op_alu, 0x11);
	case 0x12: DEC_IMM(op_alu, 0x12);
	case 0x13: DEC_IMM(op_alu, 0x13);
	case 0x14: DEC_IMM(op_alu, 0x14);
	case 0x15: DEC_IMM(op_alu, 0x15);
	case 0x16: DEC_IMM(op_alu, 0x16);
	case 0x17: DEC_IMM(op_alu, 0x17);
	case 0x25: DEC_IMM(op_alu, 0x25);
	case 0x26: DEC_IMM(op_alu, 0x26);
	case 0x27: DEC_IMM(op_alu, 0x27);
	case 0x38: return imm ? op_jmpl<true> : op_jmpl<false>;
	case 0x3c: DEC_IMM(op_saverestore, true);
	case 0x3d: DEC_IMM(op_saverestore, false);
	default:
	  return exec_slow;
	}
    default: {
      const uint32_t sz = (op3 < 0x20) ? LDST_SZ[op3 & 0xf] : 0;
      if(sz == 0 or (sz == 8 and (((inst >> 25) & 31) & 1)) or ((op3 & 0x10) and imm)) {
	return exec_slow;
      }
      switch(op3)
	{
	case 0x00: DEC_IMM(op_ldst, 0x00);
	case 0x01: DEC_IMM(op_ldst, 0x01);
	case 0x02: DEC_IMM(op_ldst, 0x02);
	case 0x03: DEC_IMM(op_ldst, 0x03);
	case 0x04: DEC_IMM(op_ldst, 0x04);
	case 0x05: DEC_IMM(op_ldst, 0x05);
	case 0x06: DEC_IMM(op_ldst, 0x06);
	case 0x07: DEC_IMM(op_ldst, 0x07);
	case 0x09: DEC_IMM(op_ldst, 0x09);
	case 0x0a: DEC_IMM(op_ldst, 0x0a);
	case 0x10: return op_ldst<0x10, false>;
	case 0x11: return op_ldst<0x11, false>;
	case 0x12: return op_ldst<0x12, false>;
	case 0x13: return op_ldst<0x13, false>;
	case 0x14: return op_ldst<0x14, false>;
	case 0x15: return op_ldst<0x15, false>;
	case 0x16: return op_ldst<0x16, false>;
	case 0x17: return op_ldst<0x17, false>;
	case 0x19: return op_ldst<0x19, false>;
	case 0x1a: return op_ldst<0x1a, false>;
	default:
	  UNREACHABLE();
	}
    }
    }
}

#undef DEC_IMM

/* ---- decoded-instruction cache (indysim's predecode; Bedichek, "decode once,
 * execute many") ----------------------------------------------------------------
 * One lazily allocated page of {handler, raw word} slots per 4 KB physical page
 * that has executed code: RAM pages by PA, PROM pages separately (the PROM is
 * never written once loaded).  A filled slot is trusted, so every write into
 * RAM must empty the slots of a page holding decoded instructions: CPU stores
 * (st_phys, op_ldst), ESP / Lance DMA (sun4m_t::dma_hook, set by main) and a
 * checkpoint restore (predecode_flush_all).  The page stays allocated, so the
 * fetch cache's pointer stays valid; the next fetch from it re-decodes.  This
 * is stricter than SPARC requires (a FLUSH is needed after modifying code), and
 * so behaves exactly as fetching the raw word every time did.
 * Build with -DPREDECODE_CHECK to compare every slot with memory at fetch. */
struct dinst_t {
  dinst_fn_t fn;
  uint32_t inst;
};
static const uint32_t DPAGE_SLOTS = 1024;
static dinst_t *g_ram_dpages[1u << 20];                     /* by RAM page (RAM is below 4 GB) */
static uint8_t g_code_page[1u << 20];                       /* that page has filled slots */
static dinst_t *g_prom_dpages[SUN4M_PROM_SIZE >> 12];
static dinst_t *g_fc_dpage = nullptr;                       /* the fetch cache page's slots */
static uint8_t *g_fc_codebit = nullptr;                     /* its g_code_page byte (PROM: a dummy) */
static uint8_t g_prom_codebit = 0;
static dinst_t g_uncached_slot;                             /* a fetch from neither RAM nor PROM */

static __attribute__((noinline)) void code_page_written(uint32_t ppn) {
  memset(g_ram_dpages[ppn], 0, DPAGE_SLOTS * sizeof(dinst_t));
  g_code_page[ppn] = 0;
}

static inline void code_write_check(uint64_t pa) {
  const uint32_t ppn = static_cast<uint32_t>(pa >> 12);
  if(__builtin_expect(g_code_page[ppn], 0)) {
    code_page_written(ppn);
  }
}

void predecode_dma_write(void *, uint64_t pa, const uint8_t *, uint32_t len) {
  for(uint64_t p = pa & ~0xfffULL; p < pa + len; p += 4096) {
    code_write_check(p);
  }
}

/* ---- board DMA race model (--dma-race) -----------------------------------------
 * Kodiak's ARM does each page chunk of a DMA write (sun4m_t::iommu_dma) as: snoop
 * the IOMMU PTE, snoop (WBINV) every 16-byte line of the chunk one at a time,
 * memcpy the chunk into DRAM, then snoop every line again -- while the core keeps
 * running.  A line the core touches after its first snoop but before the memcpy
 * is filled with the OLD bytes; if the core then stores anywhere in it before the
 * second snoop, that snoop writes the whole dirty line back over the DMA bytes.
 * ss10sim does the DMA in one step, so here each chunk gets the board's timeline
 * in instructions (snoop_insns per snoop, copy_insns per line copied) laid after
 * the previous chunk's, and every CPU RAM access is checked against the lines
 * still inside their window.  apply = put the old bytes back, as the board would.
 * Line granularity is the snoop's, 16 bytes. */
struct dma_watch_t {
  uint64_t line, t1, tm, t2, dma_id;
  uint8_t old[16];
  uint16_t mask;          /* bytes of the line the DMA wrote */
  bool filled, stale, dirty;
  uint32_t fill_pc, store_pc;
  uint64_t fill_icnt, store_icnt;
};
static uint64_t g_dr_snoop = 0, g_dr_copy = 0;
static bool g_dr_apply = false;
static std::vector<dma_watch_t> g_dw;
static uint64_t g_dr_cursor = 0, g_dr_id = 0;
static uint64_t g_dr_lines = 0, g_dr_stale = 0, g_dr_clobbers = 0;
struct dma_snap_t {
  uint64_t pa;
  uint32_t len;
  uint8_t b[4096];
};
static dma_snap_t g_snap[4];
static uint32_t g_snap_next = 0;

void watch_config(uint64_t pa, uint64_t len) {
  g_watch_lo = pa;
  g_watch_hi = pa + len;
  g_watch_on = (len != 0);
}

/* dbg (--esp-irq-at-pc): a store by this pc to the watched range releases a
 * held ESP interrupt (sun4m.hh esp_busy_until_ns) at once -- an interrupt forced into
 * the window that store opens */
static uint32_t g_irq_at_pc = 0;
void watch_irq_at_pc(uint32_t pc) {
  g_irq_at_pc = pc;
}

static void watch_access(state_t *s, uint64_t pa, bool is_store) {
  if(is_store and (s->pc == g_irq_at_pc) and (s->sun4m != nullptr) and (s->sun4m->esp_irq_at_ns != ~0ULL)) {
    s->sun4m->esp_irq_at_ns = 0;
    s->sun4m->esp_busy_until_ns = 0;
    s->sun4m->next_event_ns = 0;      /* timer_event at the next instruction */
    s->sun4m->next_event_icnt = 0;
    fprintf(stderr, "watch: icnt %llu pc %08x forces the held ESP interrupt\n",
	    static_cast<unsigned long long>(s->icnt), s->pc);
  }
  const uint64_t w = pa & ~3ULL;
  const uint32_t v = (static_cast<uint32_t>(s->mem.get<uint8_t>(w)) << 24) | (s->mem.get<uint8_t>(w + 1) << 16) |
		     (s->mem.get<uint8_t>(w + 2) << 8) | s->mem.get<uint8_t>(w + 3);
  uint32_t insn = 0;
  debug_fetch(s, s->pc, &insn);
  fprintf(stderr, "watch: icnt %llu pc %08x %s pa %llx word %08x : %s\n", static_cast<unsigned long long>(s->icnt),
	  s->pc, is_store ? "ST" : "ld", static_cast<unsigned long long>(pa), v, getAsmString(insn, s->pc).c_str());
}

void dma_race_config(uint64_t snoop_insns, uint64_t copy_insns, bool apply) {
  g_dr_snoop = snoop_insns;
  g_dr_copy = copy_insns;
  g_dr_apply = apply;
}

/* the line's window is over: a stale fill made dirty is the clobber */
static void dma_watch_retire(state_t *s, dma_watch_t &w) {
  if(w.stale and w.dirty) {
    uint32_t differ = 0;
    for(uint32_t i = 0; i < 16; i++) {
      if(((w.mask >> i) & 1) and (s->mem.get<uint8_t>(w.line + i) != w.old[i])) {
        differ++;
      }
    }
    ++g_dr_clobbers;
    fprintf(stderr, "dmarace: CLOBBER line %llx dma#%llu mask %04x: stale fill pc %08x icnt %llu (%lld after snoop1, %lld before memcpy), "
            "store pc %08x icnt %llu, %u DMA bytes differ%s\n",
            static_cast<unsigned long long>(w.line), static_cast<unsigned long long>(w.dma_id), w.mask, w.fill_pc,
            static_cast<unsigned long long>(w.fill_icnt), static_cast<long long>(w.fill_icnt - w.t1),
            static_cast<long long>(w.tm - w.fill_icnt), w.store_pc, static_cast<unsigned long long>(w.store_icnt), differ,
            (g_dr_apply and differ) ? ", reverted" : "");
    if(g_dr_apply and differ) {
      code_write_check(w.line);
      for(uint32_t i = 0; i < 16; i++) {
        if((w.mask >> i) & 1) {
          s->mem.set<uint8_t>(w.line + i, w.old[i]);
        }
      }
    }
  }
}

static void dma_race_expire(state_t *s) {
  size_t j = 0;
  for(size_t i = 0; i < g_dw.size(); i++) {
    if(s->icnt >= g_dw[i].t2) {
      dma_watch_retire(s, g_dw[i]);
    }
    else {
      g_dw[j++] = g_dw[i];
    }
  }
  g_dw.resize(j);
  g_dw_active = static_cast<uint32_t>(g_dw.size());
}

/* every window is over now: the ARM has finished its DMA calls */
static void dma_race_close(state_t *s) {
  for(dma_watch_t &w : g_dw) {
    w.t2 = std::min(w.t2, s->icnt);
  }
  g_dr_cursor = std::min(g_dr_cursor, s->icnt);
  dma_race_expire(s);
}

/* the CPU takes an interrupt with the ESP's DMA interrupt up: on the board the
 * ARM raises it only after the DMA's second snoop pass, so every window is over */
static void dma_race_interrupt(state_t *s) {
  if(g_dw_active != 0 and s->sun4m != nullptr and s->sun4m->espdma.irq) {
    dma_race_close(s);
  }
}

static void dma_race_access_slow(state_t *s, uint64_t pa, bool is_store) {
  dma_race_expire(s);
  const uint64_t line = pa & ~15ULL;
  for(dma_watch_t &w : g_dw) {
    if(w.line != line or s->icnt < w.t1) {
      continue;          /* before its first snoop, the snoop writes the core's copy back first */
    }
    if(not w.filled) {
      w.filled = true;
      w.stale = s->icnt < w.tm;
      w.fill_pc = s->pc;
      w.fill_icnt = s->icnt;
      if(w.stale) {
        ++g_dr_stale;
      }
    }
    if(is_store and w.stale and not w.dirty) {
      w.dirty = true;
      w.store_pc = s->pc;
      w.store_icnt = s->icnt;
    }
  }
}

/* sun4m_t::dma_snoop: called before (and again after) every chunk's memcpy, and
 * for DMA reads and IOMMU PTEs; keep the bytes, the write's hook finds the copy
 * taken before its memcpy as the one that differs from what it wrote */
void dma_race_snoop(void *ctx, uint64_t pa, uint32_t len) {
  state_t *s = static_cast<state_t*>(ctx);
  if(g_dr_snoop == 0 or len > 4096 or pa + len > s->ram_size) {
    return;
  }
  dma_snap_t &n = g_snap[g_snap_next++ & 3];
  n.pa = pa;
  n.len = len;
  for(uint32_t i = 0; i < len; i++) {
    n.b[i] = s->mem.get<uint8_t>(pa + i);
  }
}

/* sun4m_t::dma_hook: one chunk of a DMA write has landed in RAM */
void dma_race_write(void *ctx, uint64_t pa, const uint8_t *buf, uint32_t len) {
  state_t *s = static_cast<state_t*>(ctx);
  predecode_dma_write(ctx, pa, buf, len);
  if(g_watch_on and pa < g_watch_hi and pa + len > g_watch_lo) {
    fprintf(stderr, "watch: icnt %llu DMA write pa %llx len %u\n", static_cast<unsigned long long>(s->icnt),
	    static_cast<unsigned long long>(pa), len);
  }
  if(g_dr_snoop == 0) {
    return;
  }
  const dma_snap_t *pre = nullptr;
  for(uint32_t k = 1; k <= 4; k++) {
    const dma_snap_t &c = g_snap[(g_snap_next - k) & 3];
    if(c.pa == pa and c.len == len and memcmp(c.b, buf, len) != 0) {
      pre = &c;
      break;
    }
  }
  dma_race_expire(s);
  const uint64_t first = pa & ~15ULL;
  const uint64_t lines = ((pa + len + 15) & ~15ULL) - first;
  const uint64_t nlines = lines >> 4;
  const uint64_t t0 = std::max(s->icnt, g_dr_cursor) + g_dr_snoop;    /* the PTE snoop */
  const uint64_t tm = t0 + nlines * g_dr_snoop + nlines * g_dr_copy;
  ++g_dr_id;
  for(uint64_t i = 0; i < nlines; i++) {
    dma_watch_t w;
    memset(&w, 0, sizeof(w));
    w.line = first + 16 * i;
    w.t1 = t0 + (i + 1) * g_dr_snoop;
    w.tm = tm;
    w.t2 = tm + (i + 1) * g_dr_snoop;
    w.dma_id = g_dr_id;
    for(uint32_t b = 0; b < 16; b++) {
      const uint64_t a = w.line + b;
      if(a >= pa and a < pa + len) {
        w.mask |= static_cast<uint16_t>(1u << b);
        w.old[b] = pre ? pre->b[a - pa] : buf[a - pa];
      }
    }
    g_dw.push_back(w);
  }
  g_dr_lines += nlines;
  g_dr_cursor = tm + nlines * g_dr_snoop;
  g_dw_active = static_cast<uint32_t>(g_dw.size());
}

void dma_race_report() {
  if(g_dr_snoop != 0) {
    fprintf(stderr, "dmarace: %llu DMA chunks, %llu lines, %llu stale fills, %llu clobbers\n",
            static_cast<unsigned long long>(g_dr_id), static_cast<unsigned long long>(g_dr_lines),
            static_cast<unsigned long long>(g_dr_stale), static_cast<unsigned long long>(g_dr_clobbers));
  }
}

void predecode_flush_all() {
  for(uint32_t ppn = 0; ppn < (1u << 20); ppn++) {
    if(g_code_page[ppn]) {
      code_page_written(ppn);
    }
  }
}

static dinst_t *dpage_for(dinst_t **slot) {
  if(*slot == nullptr) {
    *slot = new dinst_t[DPAGE_SLOTS]();
  }
  return *slot;
}

/* fetch-page cache miss: translate and read the instruction the slow way,
 * taking the instruction access trap on a fault (nullptr).  On success refill
 * the cache when the page is RAM or PROM and return its slot; otherwise return
 * g_uncached_slot, decoded on the spot.  Out of line to keep exec_one small. */
static __attribute__((noinline)) dinst_t *fetch_refill(state_t *s, uint32_t pc, uint64_t ftag) {
  uint64_t fetch_pa = 0;
  if(mmu_xlate(s, s->s ? 0x9 : 0x8, pc, acc_t::fetch, &fetch_pa) != FT_NONE) {
    take_trap(s, TT_IACCESS);
    return nullptr;
  }
  const uint32_t inst = ld_phys<uint32_t>(s, fetch_pa);
  if(s->bus_error and mmu_bus_error(s, fetch_pa, false, true, false)) {
    take_trap(s, TT_IACCESS_ERROR);
    return nullptr;
  }
  const uint64_t ppage = fetch_pa & ~0xfffULL;
  if(ppage + 4096 <= s->ram_size) {
    g_fc_tag = ftag;
    g_fc_host = s->mem.get_raw_ptr(ppage);
    g_fc_dpage = dpage_for(&g_ram_dpages[ppage >> 12]);
    g_fc_codebit = &g_code_page[ppage >> 12];
  }
  else if(s->sun4m and ppage >= SUN4M_PROM_BASE and ppage + 4096 <= SUN4M_PROM_BASE + SUN4M_PROM_SIZE) {
    g_fc_tag = ftag;
    g_fc_host = &s->sun4m->prom[ppage - SUN4M_PROM_BASE];
    g_fc_dpage = dpage_for(&g_prom_dpages[(ppage - SUN4M_PROM_BASE) >> 12]);
    g_fc_codebit = &g_prom_codebit;
  }
  else {
    g_uncached_slot.inst = inst;
    g_uncached_slot.fn = decode_insn(inst);
    return &g_uncached_slot;
  }
  return &g_fc_dpage[(pc & 0xfffu) >> 2];
}

static inline uint32_t fc_word(uint32_t pc) {
  uint32_t w;
  memcpy(&w, g_fc_host + (pc & 0xfffu), 4);
  return be(w);
}

static __attribute__((noinline)) void fill_slot(dinst_t *di, uint32_t pc) {
  di->inst = fc_word(pc);
  di->fn = decode_insn(di->inst);
  if(di->inst == 0x01000000u) {
    /* the word before (same page only: a slot at offset 0 counts as not a delay slot) */
    const bool ds = ((pc & 0xfffu) != 0) and is_cti(fc_word(pc - 4));
    di->fn = ds ? op_nop<true> : op_nop<false>;
  }
  *g_fc_codebit = 1;
}

static inline __attribute__((always_inline)) void exec_one(state_t *s) {
  if(not s->ext_irq and s->et and s->irl != 0 and (s->irl == 15 or s->irl > s->pil)) {
    dma_race_interrupt(s);
    take_trap(s, TT_INTERRUPT_BASE + s->irl);
    return;
  }
  const uint32_t pc = s->pc;
  const uint64_t ftag = ((static_cast<uint64_t>(s->s) << 36) | (static_cast<uint64_t>(s->mmu_ctx) << 20) | (pc >> 12)) + 1;
  dinst_t *di;
  if(__builtin_expect(ftag == g_fc_tag, 1)) {
    di = &g_fc_dpage[(pc & 0xfffu) >> 2];
  }
  else {
    di = fetch_refill(s, pc, ftag);
    if(di == nullptr) {
      return;
    }
  }
  if(__builtin_expect(di->fn == nullptr, 0)) {
    fill_slot(di, pc);
  }
#ifdef PREDECODE_CHECK
  if(di != &g_uncached_slot and di->inst != fc_word(pc)) {
    fprintf(stderr, "predecode: stale slot at pc 0x%x icnt %llu: 0x%08x, memory 0x%08x\n", pc,
	    static_cast<unsigned long long>(s->icnt), di->inst, fc_word(pc));
    abort();
  }
#endif
  di->fn(s, di->inst);
}

void execSparc(state_t *s) {
  exec_one(s);
}

/* main's lean loop, here so exec_one inlines into it: run while icnt < lim, before
 * the sun4m's next timer event, and for at most max_n instructions; stop early
 * when the CPU halts, asks for a system reset or breaks.  Returns the number
 * executed. */
uint64_t execSparcRun(state_t *s, uint64_t lim, uint64_t max_n) {
  uint64_t n = 0;
  sun4m_t *const m4 = s->sun4m;
  if(m4) {
    while(s->icnt < lim and s->icnt < m4->next_event_icnt and n < max_n) {
      exec_one(s);
      n++;
      if(__builtin_expect(m4->cpu_halted or m4->reset_req or s->brk, 0)) {
	break;
      }
    }
  }
  else {
    while(s->icnt < lim and n < max_n and not s->brk) {
      exec_one(s);
      n++;
    }
  }
  return n;
}
