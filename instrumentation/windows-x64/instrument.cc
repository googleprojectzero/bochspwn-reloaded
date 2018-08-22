/////////////////////////////////////////////////////////////////////////
//
// Author: Mateusz Jurczyk (mjurczyk@google.com)
//
// Copyright 2017-2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "instrument.h"

#include <windows.h>

#include <stdint.h>

#include "bochs.h"
#include "cpu/cpu.h"
#include "disasm/disasm.h"

#include "breakpoints.h"
#include "common.h"
#include "logging.pb.h"
#include "mem_interface.h"
#include "os_windows.h"
#include "symbols.h"
#include "taint.h"

// ------------------------------------------------------------------
// Helper functions' implementation.
// ------------------------------------------------------------------

static void set_breakpoints_bulk(const std::vector<uint64_t>& addresses, int type) {
  for (uint64_t address : addresses) {
    bp::add_breakpoint(address, type);
  }
}

static void parse_offset_list(char *buffer, std::vector<uint64_t> *v) {
  char *pch = strtok(buffer, ",");
  while (pch != NULL) {
    uint64_t address = strtoull(pch, NULL, 16);
    v->push_back(address);

    pch = strtok(NULL, ",");
  }
}

static bool init_basic_config(const char *config_path, bochspwn_config *config) {
  static char buffer[256];

  // Output file path.
  READ_INI_STRING(config_path, "general", "log_path", buffer, sizeof(buffer));
  config->log_path = strdup(buffer);

  // System version.
  READ_INI_STRING(config_path, "general", "version", buffer, sizeof(buffer));
  config->os_version = strdup(buffer);

  // Maximum length of callstack.
  READ_INI_INT(config_path, "general", "callstack_length", buffer, sizeof(buffer),
               &config->callstack_length);

  // Symbolization settings.
  READ_INI_INT(config_path, "general", "symbolize", buffer, sizeof(buffer),
               &config->symbolize);
  READ_INI_STRING(config_path, "general", "symbol_path", buffer, sizeof(buffer));
  config->symbol_path = strdup(buffer);

  // Read the origin tracking setting.
  READ_INI_INT(config_path, "general", "track_origins", buffer, sizeof(buffer), &config->track_origins);

  // Read the uniquization setting.
  READ_INI_INT(config_path, "general", "uniquize", buffer, sizeof(buffer), &config->uniquize);

  // Read the break-on-bug setting.
  READ_INI_INT(config_path, "general", "break_on_bug", buffer, sizeof(buffer), &config->break_on_bug);

  // Read the nt!KiSystemCall64 offset.
  READ_INI_ULL(config_path, "general", "KiSystemCall64_offset", buffer, sizeof(buffer),
               &config->KiSystemCall64_offset);

  // Comma-separated list of pool allocation routine offsets.
  READ_INI_STRING(config_path, "general", "pool_alloc_prologues", buffer, sizeof(buffer));
  parse_offset_list(buffer, &config->pool_alloc_prologues);

  READ_INI_STRING(config_path, "general", "pool_alloc_epilogues", buffer, sizeof(buffer));
  parse_offset_list(buffer, &config->pool_alloc_epilogues);

  // The signature of the memcpy() function.
  READ_INI_STRING(config_path, "general", "memcpy_signature", buffer, sizeof(buffer));
  config->memcpy_signature = unhexlify(buffer);

  return true;
}

// Returns the contents of a single log record in formatted, textual form.
static std::string bug_report_as_text(const bug_report_t& bug_report) {
  char buffer[256];
  std::string ret;

  snprintf(buffer, sizeof(buffer),
           "[pid/tid: %.8x/%.8x] {%16s} COPY of %llx ---> %llx "
           "(%u bytes), pc = %llx [ %40s ]\n",
           bug_report.process_id(), bug_report.thread_id(),
           bug_report.image_file_name().c_str(),
           bug_report.lin(),
           bug_report.copy_dest_address(),
           (unsigned)bug_report.len(),
           bug_report.pc(),
           bug_report.pc_disasm().c_str());
  ret = buffer;

  if (bug_report.has_alloc_origin()) {
    snprintf(buffer, sizeof(buffer), "Allocation origin: 0x%llx (%s)\n",
             bug_report.alloc_origin(),
             symbols::symbolize_address(bug_report.alloc_origin()).c_str());
    ret += buffer;
  }

  ret += "--- Shadow memory:\n";
  ret += format_hex(bug_report.shadow_memory());

  ret += "--- Actual memory:\n";
  ret += format_hex(bug_report.region_body());

  ret += "--- Stack trace:\n";
  for (int i = 0; i < bug_report.stack_trace_size(); i++) {
    if (globals::config.symbolize) {
      snprintf(buffer, sizeof(buffer), " #%u  0x%llx ((%.8llx) %s)\n", i,
               (bug_report.stack_trace(i).module_base() + bug_report.stack_trace(i).relative_pc()),
               bug_report.stack_trace(i).relative_pc(),
               symbols::symbolize_offset(bug_report.stack_trace(i).module_name(),
                                         bug_report.stack_trace(i).relative_pc()).c_str());
    } else {
      snprintf(buffer, sizeof(buffer), " #%u  0x%llx (%s+%.8x)\n", i,
               (bug_report.stack_trace(i).module_base() + bug_report.stack_trace(i).relative_pc()),
               bug_report.stack_trace(i).module_name().c_str(),
               (unsigned)bug_report.stack_trace(i).relative_pc());
    }
    ret += buffer;
  }

  return ret;
}

__attribute__((noinline))
static void process_bug_candidate(BX_CPU_C *pcpu, bxInstruction_c *i, bx_address pc,
                                  bx_address lin, uint64_t len, uint64_t copy_dest_address,
                                  uint64_t origin) {
  // Determine if the allocation origin is unique.
  bool unique_origin = false;

  if (origin != 0) {
    unique_origin = (globals::known_origin.find(origin) == globals::known_origin.end());
    if (unique_origin) {
      globals::known_origin.insert(origin);
    }
  }

  // Obtain the stack trace and determine if it is unique.
  std::vector<callstack_item> callstack;
  bool unique_callstack = false;

  windows::get_callstack(pcpu, &callstack);

  for (size_t i = 0; i < callstack.size(); i++) {
    if (globals::known_callstack_item.find(callstack[i].module_base + callstack[i].relative_pc) ==
        globals::known_callstack_item.end()) {
      unique_callstack = true;
      globals::known_callstack_item.insert(callstack[i].module_base + callstack[i].relative_pc);
    }
  }

  if (!unique_origin && !unique_callstack) {
    return;
  }
 
  bug_report_t bug_report;
  bug_report.set_lin(lin);
  bug_report.set_len(len);
  bug_report.set_pc(pc);

  windows::fill_system_info(pcpu, &bug_report);
  
  for (auto& item : callstack) {
    bug_report_t::callstack_item *new_item = bug_report.add_stack_trace();
    new_item->set_relative_pc(item.relative_pc);
    new_item->set_module_base(item.module_base);
    new_item->set_module_name(item.module_name);
  }

  static Bit8u ibuf[32] = {0};
  static char pc_disasm[64];
  if (read_lin_mem(pcpu, pc, sizeof(ibuf), ibuf)) {
    disassembler bx_disassemble;
    bx_disassemble.disasm(/*is_32=*/false, /*is_64=*/true, /*cs_base=*/0, pc, ibuf, pc_disasm);
  }
  bug_report.set_pc_disasm(pc_disasm);

  bug_report.set_copy_dest_address(copy_dest_address);
  bug_report.set_alloc_origin(origin);

  uint8_t *shadow_memory = (uint8_t *)calloc(len, 1);
  taint::get_shadow_memory(lin, len, shadow_memory);
  bug_report.set_shadow_memory(shadow_memory, len);
  free(shadow_memory);

  uint8_t *memory_region = (uint8_t *)calloc(len, 1);
  read_lin_mem(pcpu, lin, len, memory_region);
  bug_report.set_region_body(memory_region, len);
  free(memory_region);

  FILE *f = globals::config.file_handle;
  fprintf(f, "\n------------------------------ found uninit-copy of address %llx\n\n", bug_report.lin());
  fprintf(f, "%s", bug_report_as_text(bug_report).c_str());
  fflush(f);

  if (globals::config.break_on_bug) {
    invoke_guest_int3(pcpu, /*rip_is_cur_instr=*/true, i);
  }
}

static void handle_memcpy(
    BX_CPU_C *pcpu, bxInstruction_c *i, uint64_t dst, uint64_t src, uint64_t size) {
  if (size == 0) {
    return;
  }

  const bool dst_in_kernel = windows::check_kernel_addr(dst);
  const bool src_in_kernel = windows::check_kernel_addr(src);

  if (!dst_in_kernel && !src_in_kernel) {
    return;
  }

  if (dst_in_kernel && src_in_kernel) {
    taint::copy_taint(dst, src, size);

    if (globals::config.track_origins) {
      taint::copy_origin(dst, src, size);
    }
  } else if (dst_in_kernel) {
    taint::set_taint(dst, size, /*tainted=*/false);
  } else /* src_in_kernel */ {
    uint64_t tainted_offset = 0;
    taint::access_type type = taint::check_taint(pcpu, src, size, &tainted_offset);

    if (type == taint::METADATA_MARKER_MISMATCH) {
      taint::set_taint(src, size, /*tainted=*/false);
    } else if (type == taint::ACCESS_INVALID) {
      process_bug_candidate(
          pcpu, i, pcpu->prev_rip, src, size, dst, taint::get_origin(src + tainted_offset));
    }
  }
}

// ------------------------------------------------------------------
// Instrumentation implementation.
// ------------------------------------------------------------------

void bx_instr_initialize(unsigned cpu) {
  // Obtain configuration file path.
  char *conf_path = NULL;
  if (conf_path = getenv(kConfFileEnvVariable), conf_path == NULL) {
    fprintf(stderr, "Configuration file not specified in \"%s\"\n",
            kConfFileEnvVariable);
    abort();
  }

  // Read basic configuration from .ini file.
  if (!init_basic_config(conf_path, &globals::config)) {
    fprintf(stderr, "Initialization with config file \"%s\" failed\n", conf_path);
    abort();
  }

  // Initialize output file handle for the first time.
  globals::config.file_handle = fopen(globals::config.log_path, "wb");
  if (!globals::config.file_handle) {
    fprintf(stderr, "Unable to open the \"%s\" log file\n", globals::config.log_path);
    abort();
  }

  // Allow the guest-specific part to initialize (read internal offsets etc).
  if (!windows::init(conf_path)) {
    fprintf(stderr, "Guest-specific initialization with file \"%s\" failed\n", conf_path);
    abort();
  }

  // Initialize symbols subsystem.
  symbols::initialize();

  // Initialize the taint subsystem.
  taint::initialize();

  // Initialize helper taint allocations.
  globals::pool_taint_alloc = (uint8_t *)malloc(kTaintHelperAllocSize);
  memset(globals::pool_taint_alloc, kPoolTaintByte, kTaintHelperAllocSize);

  globals::stack_taint_alloc = (uint8_t *)malloc(kTaintHelperAllocSize);
  memset(globals::stack_taint_alloc, kStackTaintByte, kTaintHelperAllocSize);
}

void bx_instr_exit(unsigned cpu) {
  // Free the symbols subsystem.
  symbols::destroy();

  // Destroy the taint subsystem.
  taint::destroy();
}

void bx_instr_interrupt(unsigned cpu, unsigned vector) {
  if (globals::bp_active && vector == 3) {
    BX_CPU_C *pcpu = BX_CPU(cpu);
    write_lin_mem(pcpu, globals::bp_address, 1, &globals::bp_orig_byte);

    globals::bp_active = false;
  }
}

void bx_instr_before_execution(unsigned cpu, bxInstruction_c *i) {
  BX_CPU_C *pcpu = BX_CPU(cpu);
  const bx_address pc = pcpu->prev_rip;

  if (!pcpu->long_mode() || !windows::check_kernel_addr(pc)) {
    return;
  }

  const unsigned int opcode = i->getIaOpcode();
  switch (opcode) {
    case BX_IA_MOV_GqEq: /* Standard library memcpy() prologue handling. */ {
      if (i->modC0() && i->dst() == BX_64BIT_REG_R11 && i->src() == BX_64BIT_REG_RCX) {
        auto it = globals::is_address_memcpy.find(pc);
        bool is_memcpy;

        if (it == globals::is_address_memcpy.end()) {
          Bit8u ibuf[16] = { /* zero padding */ };
          read_lin_mem(pcpu, pc, sizeof(ibuf), ibuf);

          if (!memcmp(ibuf,
                      globals::config.memcpy_signature.data(),
                      globals::config.memcpy_signature.size())) {
            globals::is_address_memcpy[pc] = true;
            is_memcpy = true;
          } else {        
            globals::is_address_memcpy[pc] = false;
            is_memcpy = false;
          }
        } else {
          is_memcpy = it->second;
        }

        if (is_memcpy) {
          const uint64_t dst = pcpu->gen_reg[BX_64BIT_REG_RCX].rrx;
          const uint64_t src = pcpu->gen_reg[BX_64BIT_REG_RDX].rrx;
          const uint64_t size = pcpu->gen_reg[BX_64BIT_REG_R8].rrx;

          handle_memcpy(pcpu, i, dst, src, size);

          const uint64_t rsp = pcpu->gen_reg[BX_64BIT_REG_RSP].rrx;
          globals::rsp_locked.insert(rsp);
        }
      }
      break;
    }

    case BX_IA_REP_MOVSB_YbXb:
    case BX_IA_REP_MOVSW_YwXw:
    case BX_IA_REP_MOVSD_YdXd:
    case BX_IA_REP_MOVSQ_YqXq: /* Inline memcpy handling */ {
      const uint64_t dst = pcpu->gen_reg[BX_64BIT_REG_RDI].rrx;
      const uint64_t src = pcpu->gen_reg[BX_64BIT_REG_RSI].rrx;
      const uint64_t size = pcpu->gen_reg[BX_64BIT_REG_RCX].rrx;
      uint64_t mult = 0;
      
      switch (opcode) {
        case BX_IA_REP_MOVSB_YbXb: mult = 1; break;
        case BX_IA_REP_MOVSW_YwXw: mult = 2; break;
        case BX_IA_REP_MOVSD_YdXd: mult = 4; break;
        case BX_IA_REP_MOVSQ_YqXq: mult = 8; break;
      }

      handle_memcpy(pcpu, i, dst, src, size * mult);

      globals::rep_movs = true;
      break;
    }

    case BX_IA_SUB_EqId:
    case BX_IA_SUB_GqEq: /* Stack allocation handling */ {
      if (i->dst() != BX_64BIT_REG_RSP) {
        break;
      }
      if (opcode == BX_IA_SUB_GqEq && (!i->modC0() || i->src() != BX_64BIT_REG_RAX)) {
        break;
      }

      const uint64_t rsp = pcpu->gen_reg[BX_64BIT_REG_RSP].rrx;
      if (windows::check_kernel_addr(rsp)) {
        globals::rsp_change = true;
        globals::rsp_value = rsp;
      }

      break;
    }

    case BX_IA_PUSH_Eq: /* Allocator prologue handling. */ {
      if (!i->modC0() || i->dst() != BX_64BIT_REG_RBP) {
        break;
      }

      if (bp::check_breakpoint(pc) == BP_POOL_ALLOC_PROLOGUE) {
        const uint64_t rsp = pcpu->gen_reg[BX_64BIT_REG_RSP].rrx;
        const uint64_t size = pcpu->gen_reg[BX_64BIT_REG_RDX].rrx;
        uint64_t origin = 0;
        read_lin_mem(pcpu, rsp, sizeof(origin), &origin);

        globals::pending_allocs[rsp].size = size; 
        globals::pending_allocs[rsp].origin = origin;
      }

      break;
    }

    case BX_IA_RET_Op64: /* Allocator and memcpy() epilogue handling. */ {
      // Unlock the current rsp in case we're returning from memcpy().
      const uint64_t rsp = pcpu->gen_reg[BX_64BIT_REG_RSP].rrx;
      globals::rsp_locked.erase(rsp);

      // Check if we're leaving an allocator function.
      if (bp::check_breakpoint(pc) == BP_POOL_ALLOC_EPILOGUE) {
        auto it = globals::pending_allocs.find(rsp);
        uint64_t size = 0;
        uint64_t address = pcpu->gen_reg[BX_64BIT_REG_RAX].rrx;
        uint64_t origin = 0;

        if (it != globals::pending_allocs.end()) {
          size = it->second.size;
          origin = it->second.origin;
          globals::pending_allocs.erase(it);
        }

        if (size != 0 && address != 0) {
          const unsigned int kPageAllocBoundary = 4080;
          if (size <= kPageAllocBoundary) {
            taint::set_taint(address, size, /*tainted=*/true);
            write_lin_mem(pcpu, address, size, (void *)globals::pool_taint_alloc);

            if (globals::config.track_origins) {
              taint::set_origin(address, size, origin);
            }
          } else {
            taint::set_taint(address, size, /*tainted=*/false);
          }
        }
      }

      break;
    }
  }
}

void bx_instr_after_execution(unsigned cpu, bxInstruction_c *i) {
  globals::rep_movs = false;

  if (globals::rsp_change) {
    BX_CPU_C *pcpu = BX_CPU(cpu);
    const uint64_t new_rsp = pcpu->gen_reg[BX_64BIT_REG_RSP].rrx;

    if (new_rsp < globals::rsp_value) {
      uint64_t length = globals::rsp_value - new_rsp;

      if (length <= kTaintHelperAllocSize) {
        taint::set_taint(new_rsp, length, /*tainted=*/true);
        write_lin_mem(pcpu, new_rsp, length, (void *)globals::stack_taint_alloc);

        if (globals::config.track_origins) {
          taint::set_origin(new_rsp, length, pcpu->prev_rip);
        }
      }
    }

    globals::rsp_change = false;
    globals::rsp_value = 0;
  }
}

void bx_instr_lin_access(unsigned cpu, bx_address lin, bx_address phy,
                         unsigned len, unsigned memtype, unsigned rw) {
  BX_CPU_C *pcpu = BX_CPU(cpu);
  const uint64_t pc = pcpu->prev_rip;

  if (rw != BX_WRITE && rw != BX_RW) {
    return;
  }

  if (!pcpu->long_mode() || !windows::check_kernel_addr(pc) || !windows::check_kernel_addr(lin)) {
    return;
  }

  if (globals::rep_movs) {
    return;
  }

  const uint64_t rsp = pcpu->gen_reg[BX_64BIT_REG_RSP].rrx;
  if (globals::rsp_locked.find(rsp) != globals::rsp_locked.end()) {
    return;
  }

  taint::set_taint(lin, len, /*tainted=*/false);
}

void bx_instr_wrmsr(unsigned cpu, unsigned addr, Bit64u value) {
  if (addr == MSR_LSTAR) {
    globals::nt_base = value - globals::config.KiSystemCall64_offset;

    for (size_t i = 0; i < globals::config.pool_alloc_prologues.size(); i++) {
      globals::config.pool_alloc_prologues[i] += globals::nt_base;
    }
    set_breakpoints_bulk(globals::config.pool_alloc_prologues, BP_POOL_ALLOC_PROLOGUE);

    for (size_t i = 0; i < globals::config.pool_alloc_epilogues.size(); i++) {
      globals::config.pool_alloc_epilogues[i] += globals::nt_base;
    }
    set_breakpoints_bulk(globals::config.pool_alloc_epilogues, BP_POOL_ALLOC_EPILOGUE);
  }
}

